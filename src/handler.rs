/// WebSocket client handler for 0trace traceroute

use crate::connection::{extract_connection_params, extract_real_client_ip};
use crate::constants::*;
use crate::events::event_bus;
use crate::network::{create_icmp_socket, create_raw_socket, poll_icmp_responses, send_tcp_probe};
use crate::types::Hop;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{ErrorResponse, Request, Response},
    tungstenite::Message,
};

type MiddlewareChannel = tokio::sync::mpsc::UnboundedSender<(
    String,
    tokio::sync::mpsc::UnboundedSender<napi::bindgen_prelude::Promise<String>>,
)>;

/// Handle a single WebSocket client connection and perform 0trace traceroute
pub async fn handle_client(
    tcp_stream: TcpStream,
    peer_address: SocketAddr,
    max_hops: u8,
    ttl_timeout: Duration,
    middleware_channel: Option<MiddlewareChannel>,
) {
    let client_id = format!("{}", peer_address);
    
    // Extract real client IP and connection parameters
    let (real_client_ip, websocket_stream, connection_params) =
        match setup_websocket_connection(tcp_stream, peer_address, &client_id).await {
            Ok(result) => result,
            Err(_) => return,
        };
    
    event_bus().emit(
        "clientConnected",
        &serde_json::json!({ "clientId": client_id }),
    );
    
    eprintln!(
        "[DEBUG handler] Connection established: {}:{} <-> {}:{}",
        connection_params.local_ip,
        connection_params.local_port,
        real_client_ip,
        connection_params.peer_port
    );
    
    // Create network sockets for sending probes and receiving ICMP
    let (raw_socket_fd, icmp_socket_fd) = match setup_network_sockets(&client_id) {
        Ok(sockets) => sockets,
        Err(_) => return,
    };
    
    // Split WebSocket for concurrent read/write
    let (websocket_writer, websocket_reader) = websocket_stream.split();
    
    // Send greeting message
    let websocket_writer = match send_greeting(websocket_writer).await {
        Ok(writer) => writer,
        Err(_) => {
            cleanup_sockets(raw_socket_fd, icmp_socket_fd);
            return;
        }
    };
    
    // Run traceroute
    let (completion_signal_tx, completion_signal_rx) = oneshot::channel::<()>();
    
    let traceroute_task = tokio::spawn(run_traceroute(
        client_id.clone(),
        raw_socket_fd,
        icmp_socket_fd,
        connection_params.local_ip,
        connection_params.local_port,
        real_client_ip,
        connection_params.peer_port,
        max_hops,
        ttl_timeout,
        websocket_writer,
        middleware_channel,
        completion_signal_tx,
    ));
    
    // Handle incoming WebSocket messages
    let message_handler_task = tokio::spawn(handle_websocket_messages(websocket_reader));
    
    // Wait for completion
    let _ = completion_signal_rx.await;
    let _ = traceroute_task.await;
    let _ = message_handler_task.await;
    
    cleanup_sockets(raw_socket_fd, icmp_socket_fd);
    event_bus().emit("clientDone", &serde_json::json!({ "clientId": client_id }));
}

/// Setup WebSocket connection and extract connection parameters
async fn setup_websocket_connection(
    tcp_stream: TcpStream,
    peer_address: SocketAddr,
    client_id: &str,
) -> Result<(std::net::Ipv4Addr, tokio_tungstenite::WebSocketStream<TcpStream>, crate::connection::ConnectionParams), ()> {
    // Extract connection parameters before WebSocket upgrade
    let connection_params = match extract_connection_params(&tcp_stream) {
        Ok(params) => params,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": client_id, "message": format!("Failed to extract connection params: {}", e)}),
            );
            return Err(());
        }
    };
    
    // Store real client IP from headers
    let real_client_ip = std::sync::Arc::new(std::sync::Mutex::new(None::<std::net::Ipv4Addr>));
    let real_client_ip_clone = real_client_ip.clone();
    
    // WebSocket handshake callback to extract headers
    let handshake_callback = move |request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
        let extracted_ip = extract_real_client_ip(request, peer_address);
        *real_client_ip_clone.lock().unwrap() = Some(extracted_ip);
        
        response.headers_mut()
            .insert("X-ZeroTrace", "ok".parse().unwrap());
        Ok(response)
    };
    
    // Perform WebSocket handshake
    let websocket_stream = match accept_hdr_async(tcp_stream, handshake_callback).await {
        Ok(stream) => stream,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": client_id, "message": format!("WebSocket handshake failed: {}", e)}),
            );
            return Err(());
        }
    };
    
    let real_ip = real_client_ip
        .lock()
        .unwrap()
        .unwrap_or_else(|| extract_real_client_ip(&Request::default(), peer_address));
    
    Ok((real_ip, websocket_stream, connection_params))
}

/// Create raw IP socket and ICMP capture socket
fn setup_network_sockets(client_id: &str) -> Result<(i32, i32), ()> {
    let raw_socket = match create_raw_socket() {
        Ok(fd) => fd,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": client_id, "message": format!("Failed to create raw socket: {}", e)}),
            );
            return Err(());
        }
    };
    
    let icmp_socket = match create_icmp_socket() {
        Ok(fd) => fd,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": client_id, "message": format!("Failed to create ICMP socket: {}", e)}),
            );
            unsafe { libc::close(raw_socket) };
            return Err(());
        }
    };
    
    Ok((raw_socket, icmp_socket))
}

/// Send greeting message to client
async fn send_greeting(
    mut writer: futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>,
) -> Result<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>, ()> {
    if writer
        .send(Message::Text(
            r#"{"type":"connected","message":"Trace started automatically"}"#.into(),
        ))
        .await
        .is_err()
    {
        eprintln!("[DEBUG handler] Failed to send greeting");
        return Err(());
    }
    Ok(writer)
}

/// Run the complete traceroute process using 0trace technique
#[allow(clippy::too_many_arguments)]
async fn run_traceroute(
    client_id: String,
    raw_socket_fd: i32,
    icmp_socket_fd: i32,
    source_ip: std::net::Ipv4Addr,
    source_port: u16,
    dest_ip: std::net::Ipv4Addr,
    dest_port: u16,
    max_hops: u8,
    ttl_timeout: Duration,
    websocket_writer: futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>,
    middleware_channel: Option<MiddlewareChannel>,
    completion_signal: oneshot::Sender<()>,
) {
    eprintln!(
        "[DEBUG handler] Starting 0trace: {}:{} -> {}:{}",
        source_ip, source_port, dest_ip, dest_port
    );
    
    // Generate base sequence number
    let sequence_base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() & 0xFFFFFFFF) as u32;
    
    // Track probes: IP ID -> (TTL, send_time)
    let mut probe_tracker = std::collections::HashMap::new();
    
    // Channels for processing pipeline
    let (hop_queue_tx, hop_queue_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let (websocket_message_tx, websocket_message_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    
    // Task to write messages to WebSocket
    let websocket_writer_task = spawn_websocket_writer_task(websocket_writer, websocket_message_rx);
    
    // Task to process hops through middleware
    let middleware_task = spawn_middleware_processor_task(
        hop_queue_rx,
        middleware_channel,
        websocket_message_tx.clone(),
    );
    
    // STEP 1: Send all probes at once (0trace technique)
    eprintln!("[DEBUG handler] Sending {} probes (TTL 1-{})", max_hops, max_hops);
    
    for ttl in 1..=max_hops {
        let send_time = Instant::now();
        
        match send_tcp_probe(
            raw_socket_fd,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            ttl,
            sequence_base,
        ) {
            Ok(ip_id) => {
                probe_tracker.insert(ip_id, (ttl, send_time));
                eprintln!("[DEBUG handler] Sent probe TTL={}, IP_ID={}", ttl, ip_id);
            }
            Err(e) => {
                eprintln!("[DEBUG handler] Failed to send probe TTL={}: {}", ttl, e);
            }
        }
        
        tokio::time::sleep(Duration::from_micros(PROBE_SEND_DELAY_MICROS)).await;
    }
    
    // STEP 2: Collect ICMP responses
    eprintln!(
        "[DEBUG handler] All probes sent, collecting {} ICMP responses",
        probe_tracker.len()
    );
    
    let collection_deadline = Instant::now() + ttl_timeout * COLLECTION_TIMEOUT_MULTIPLIER;
    let total_probes = probe_tracker.len();
    
    while !probe_tracker.is_empty() && Instant::now() < collection_deadline {
        let expected_ids: std::collections::HashMap<u16, u8> = probe_tracker
            .iter()
            .map(|(ip_id, (ttl, _))| (*ip_id, *ttl))
            .collect();
        
        let remaining_time = collection_deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(500) as u64;
        
        if remaining_time == 0 {
            break;
        }
        
        match poll_icmp_responses(icmp_socket_fd, &expected_ids, remaining_time).await {
            Ok(Some((ip_id, hop_info))) => {
                if let Some((ttl, send_time)) = probe_tracker.remove(&ip_id) {
                    let rtt_ms = send_time.elapsed().as_secs_f64() * 1000.0;
                    
                    eprintln!(
                        "[DEBUG handler] Response for TTL={}: {} ({:.2}ms) [{}/{}]",
                        ttl,
                        hop_info.router_ip,
                        rtt_ms,
                        total_probes - probe_tracker.len(),
                        total_probes
                    );
                    
                    process_hop_response(
                        &client_id,
                        ttl,
                        hop_info,
                        rtt_ms,
                        &hop_queue_tx,
                    );
                }
            }
            Ok(None) => {
                // Timeout - continue
            }
            Err(e) => {
                eprintln!("[DEBUG handler] ICMP poll error: {}", e);
            }
        }
    }
    
    // Report timeouts for remaining probes
    for (_ip_id, (ttl, _)) in probe_tracker {
        eprintln!("[DEBUG handler] Timeout for TTL={}", ttl);
        let _ = hop_queue_tx.send(serde_json::json!({
            "type": "hop",
            "ttl": ttl,
            "timeout": true
        }));
    }
    
    // Cleanup and wait for all tasks
    drop(hop_queue_tx);
    let _ = middleware_task.await;
    
    drop(websocket_message_tx);
    let mut websocket_writer = websocket_writer_task.await.unwrap();
    
    let _ = websocket_writer
        .send(Message::Text(
            r#"{"type":"clientDone","message":"zerotrace done"}"#.into(),
        ))
        .await;
    
    let _ = completion_signal.send(());
}

/// Process a hop response and queue it for middleware
fn process_hop_response(
    client_id: &str,
    ttl: u8,
    hop_info: crate::icmp::HopInfo,
    rtt_ms: f64,
    hop_queue: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
) {
    // Emit event
    let modifications_opt = if hop_info.modifications.ttl_modified
        || hop_info.modifications.flags_modified
        || hop_info.modifications.options_stripped
        || hop_info.modifications.tcp_flags_modified
        || !hop_info.modifications.modifications.is_empty()
    {
        Some(hop_info.modifications.clone())
    } else {
        None
    };
    
    let hop = Hop {
        client_id: client_id.to_string(),
        ttl,
        router: hop_info.router_ip.clone(),
        rtt_ms,
        modifications: modifications_opt.clone(),
    };
    
    event_bus().emit("hop", &serde_json::to_value(&hop).unwrap());
    
    // Prepare JSON for WebSocket
    let mpls_json: Vec<serde_json::Value> = hop_info
        .mpls_labels
        .iter()
        .map(|label| {
            serde_json::json!({
                "label": label.label,
                "exp": label.experimental_bits,
                "ttl": label.ttl
            })
        })
        .collect();
    
    let modifications_json = modifications_opt.map(|mods| {
        serde_json::json!({
            "ttl_modified": mods.ttl_modified,
            "flags_modified": mods.flags_modified,
            "options_stripped": mods.options_stripped,
            "tcp_flags_modified": mods.tcp_flags_modified,
            "modifications": mods.modifications
        })
    });
    
    let hop_message = serde_json::json!({
        "type": "hop",
        "clientId": client_id,
        "ttl": ttl,
        "ip": hop_info.router_ip,
        "router": hop_info.router_ip,
        "rtt_ms": rtt_ms,
        "mpls": mpls_json,
        "modifications": modifications_json
    });
    
    let _ = hop_queue.send(hop_message);
}

/// Spawn task to write messages to WebSocket
fn spawn_websocket_writer_task(
    mut writer: futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>,
    mut message_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> tokio::task::JoinHandle<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>> {
    tokio::spawn(async move {
        while let Some(json_str) = message_rx.recv().await {
            let _ = writer.send(Message::Text(json_str)).await;
        }
        writer
    })
}

/// Spawn task to process hops through middleware
fn spawn_middleware_processor_task(
    mut hop_queue: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    middleware_channel: Option<MiddlewareChannel>,
    websocket_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(hop_message) = hop_queue.recv().await {
            let json_str = serde_json::to_string(&hop_message).unwrap();
            
            if let Some(ref middleware_tx) = middleware_channel {
                // Request Promise from middleware
                let (promise_tx, mut promise_rx) = tokio::sync::mpsc::unbounded_channel();
                
                if middleware_tx.send((json_str.clone(), promise_tx)).is_err() {
                    let _ = websocket_tx.send(json_str);
                    continue;
                }
                
                // Await Promise in separate task
                let ws_tx = websocket_tx.clone();
                let fallback_json = json_str;
                tokio::spawn(async move {
                    match promise_rx.recv().await {
                        Some(promise) => match promise.await {
                            Ok(enriched) => {
                                let _ = ws_tx.send(enriched);
                            }
                            Err(_) => {
                                let _ = ws_tx.send(fallback_json);
                            }
                        },
                        None => {
                            let _ = ws_tx.send(fallback_json);
                        }
                    }
                });
            } else {
                let _ = websocket_tx.send(json_str);
            }
        }
    })
}

/// Handle incoming WebSocket messages from client
async fn handle_websocket_messages(
    mut reader: futures::stream::SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>,
) {
    while let Some(message) = reader.next().await {
        match message {
            Ok(Message::Text(text)) => {
                eprintln!("[DEBUG handler] Received message: {}", text);
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

/// Cleanup network sockets
fn cleanup_sockets(raw_socket_fd: i32, icmp_socket_fd: i32) {
    unsafe {
        libc::close(raw_socket_fd);
        libc::close(icmp_socket_fd);
    }
    eprintln!("[DEBUG handler] Closed network sockets");
}
