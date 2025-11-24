use crate::events::event_bus;
use crate::socket::{create_raw_socket, create_icmp_socket, poll_icmp_any, send_tcp_probe};
use crate::types::Hop;
use futures::{SinkExt, StreamExt};
use std::net::{SocketAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::Duration;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response, ErrorResponse},
    tungstenite::Message,
};

/// Handle a single WebSocket client connection and perform traceroute
/// 
/// This implements the 0trace technique: sending crafted TCP packets with
/// incrementing TTL values to discover network hops. When a packet's TTL
/// expires at a router, that router sends back an ICMP Time Exceeded message
/// which we capture to identify the hop.
/// 
/// The process:
/// 1. Accept WebSocket connection from client
/// 2. Create a raw IP socket for sending custom TCP packets
/// 3. For each TTL (1..max_hops):
///    - Send a crafted TCP packet mimicking the real connection
///    - Wait for ICMP Time Exceeded response from intermediate router
///    - Report the router's IP and RTT to client via WebSocket
pub async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    max_hops: u8,
    ttl_timeout: Duration,
    middleware_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::types::MiddlewareRequest>>,
) {
    let peer_id = format!("{}", peer);
    
    // Will store real client IP from headers
    let real_client_ip = std::sync::Arc::new(std::sync::Mutex::new(None::<Ipv4Addr>));
    let real_client_ip_clone = real_client_ip.clone();

    // Do WebSocket handshake
    let cb = move |req: &Request,
              mut resp: Response|
     -> Result<Response, ErrorResponse> {
        // Try to get real IP from proxy headers
        if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                // X-Forwarded-For can be "client, proxy1, proxy2"
                if let Some(client_ip) = forwarded_str.split(',').next() {
                    if let Ok(ip) = client_ip.trim().parse::<Ipv4Addr>() {
                        eprintln!("[DEBUG handler] Real client IP from X-Forwarded-For: {}", ip);
                        *real_client_ip_clone.lock().unwrap() = Some(ip);
                    }
                }
            }
        } else if let Some(real_ip) = req.headers().get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    eprintln!("[DEBUG handler] Real client IP from X-Real-IP: {}", ip);
                    *real_client_ip_clone.lock().unwrap() = Some(ip);
                }
            }
        }
        
        resp.headers_mut()
            .insert("X-ZeroTrace", "ok".parse().unwrap());
        Ok(resp)
    };
    
    let ws = match accept_hdr_async(stream, cb).await {
        Ok(ws) => ws,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"message": format!("handshake error from {}: {}", peer_id, e)}),
            );
            return;
        }
    };

    event_bus().emit(
        "clientConnected",
        &serde_json::json!({ "clientId": peer_id }),
    );

    // Extract connection details from the established TCP socket
    let tcp = ws.get_ref();
    let tcp_fd = tcp.as_raw_fd();
    
    // Get the actual WebSocket connection parameters (as seen from inside container)
    let (ws_local_addr, ws_peer_addr) = unsafe {
        let mut local: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let ret = libc::getsockname(tcp_fd, &mut local as *mut _ as *mut libc::sockaddr, &mut local_len);
        if ret != 0 {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": peer_id, "message": "getsockname failed"}),
            );
            return;
        }
        
        let mut peer: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let ret = libc::getpeername(tcp_fd, &mut peer as *mut _ as *mut libc::sockaddr, &mut peer_len);
        if ret != 0 {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": peer_id, "message": "getpeername failed"}),
            );
            return;
        }
        
        let local_in = &*((&local) as *const _ as *const libc::sockaddr_in);
        let local_ip = Ipv4Addr::from(u32::from_be(local_in.sin_addr.s_addr));
        let local_port = u16::from_be(local_in.sin_port);
        
        let peer_in = &*((&peer) as *const _ as *const libc::sockaddr_in);
        let peer_ip = Ipv4Addr::from(u32::from_be(peer_in.sin_addr.s_addr));
        let peer_port = u16::from_be(peer_in.sin_port);
        
        ((local_ip, local_port), (peer_ip, peer_port))
    };
    
    eprintln!("[DEBUG handler] WebSocket connection: {}:{} <-> {}:{}", 
        ws_local_addr.0, ws_local_addr.1, ws_peer_addr.0, ws_peer_addr.1);
    
    // Get REAL client IP from headers (required behind proxy like Traefik)
    let real_client_ip = if let Some(real_ip) = *real_client_ip.lock().unwrap() {
        eprintln!("[DEBUG handler] Real client IP from headers: {}", real_ip);
        real_ip
    } else {
        eprintln!("[DEBUG handler] No X-Forwarded-For or X-Real-IP header found!");
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                eprintln!("[DEBUG handler] WARNING: Using peer IP {} (likely proxy!)", ip);
                ip
            },
            _ => {
                eprintln!("[DEBUG handler] IPv6 not supported");
                return;
            }
        }
    };
    
    // 0trace approach: Use ACTUAL WebSocket connection parameters
    // Send probe packets that perfectly mimic the real WebSocket connection:
    // - Same source IP:port (container side of WebSocket)
    // - Same dest IP:port (client side of WebSocket)
    // This makes probes indistinguishable from the real connection, avoiding:
    // 1. Port scanning detection (sending to 80/443 when client uses different port)
    // 2. IDS/IPS triggers (suspicious traffic patterns)
    // 3. Makes probes look like legitimate retransmissions/packet loss
    let trace_params = (ws_local_addr.0, ws_local_addr.1, real_client_ip, ws_peer_addr.1);
    
    eprintln!("[DEBUG handler] Trace packets: {}:{} -> {}:{}", 
        trace_params.0, trace_params.1, trace_params.2, trace_params.3);
    eprintln!("[DEBUG handler] (Mimicking actual WebSocket connection for stealth)");

    // Create a raw IP socket for sending custom TCP packets with specific TTL
    // This is the key to 0trace: we send packets that mimic the real connection
    // but with low TTL values to trigger ICMP responses from routers
    let raw_fd = match create_raw_socket() {
        Ok(fd) => fd,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": peer_id, "message": format!("create raw socket failed: {}", e)}),
            );
            return;
        }
    };

    // Create a raw ICMP socket for receiving ICMP Time Exceeded messages
    // Unlike MSG_ERRQUEUE approach, we create a separate socket that receives
    // ALL ICMP packets, then filter for Time Exceeded messages matching our IP IDs
    // This is similar to how the Go implementation uses pcap to capture ICMP
    let icmp_fd = match create_icmp_socket(Some(ws_local_addr.0)) {
        Ok(fd) => fd,
        Err(e) => {
            event_bus().emit(
                "error",
                &serde_json::json!({"clientId": peer_id, "message": format!("create ICMP socket failed: {}", e)}),
            );
            unsafe { libc::close(raw_fd) };
            return;
        }
    };

    // Ensure sockets are cleaned up on all exit paths
    let raw_fd_arc = std::sync::Arc::new(std::sync::Mutex::new(Some(raw_fd)));
    let icmp_fd_arc = std::sync::Arc::new(std::sync::Mutex::new(Some(icmp_fd)));
    let raw_fd_cleanup = raw_fd_arc.clone();
    let icmp_fd_cleanup = icmp_fd_arc.clone();

    // Split WebSocket so we can send/receive
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Send greeting
    if let Err(e) = ws_writer
        .send(Message::Text(r#"{"type":"connected","message":"Trace started automatically"}"#.into()))
        .await {
        eprintln!("[DEBUG handler] Failed to send greeting: {}", e);
        // Clean up sockets before returning
        if let Some(fd) = raw_fd_cleanup.lock().unwrap().take() {
            unsafe { libc::close(fd); }
        }
        if let Some(fd) = icmp_fd_cleanup.lock().unwrap().take() {
            unsafe { libc::close(fd); }
        }
        return;
    }

    // 0trace approach: Send ALL probe packets immediately, then collect ICMP responses
    // This is the key difference from traditional traceroute which sends one packet,
    // waits for response, then sends the next one
    
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let peer_id_clone = peer_id.clone();
    let middleware_tx_clone = middleware_tx.clone();
    
    // Generate a base TCP sequence number for our probe packets
    let seq_base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() & 0xFFFFFFFF) as u32;

    
    let trace_task = tokio::spawn(async move {
        // Map to track IP IDs -> (TTL, send_time)
        let mut probe_map = std::collections::HashMap::new();
        
        // Queue for hop messages to process through middleware
        let (hop_tx, mut hop_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        
        // Spawn task to process hop queue through middleware
        let middleware_task = {
            let middleware_tx = middleware_tx_clone.clone();
            let mut ws_writer_clone = ws_writer;
            tokio::spawn(async move {
                while let Some(hop_msg) = hop_rx.recv().await {
                    // If middleware is provided, call it to enrich the data
                    if let Some(ref mw_tx) = middleware_tx {
                        let json_str = serde_json::to_string(&hop_msg).unwrap();
                        eprintln!("[DEBUG handler] Sending to middleware: {}", json_str);
                        
                        // Create channel to receive enriched data
                        let (response_tx, response_rx) = tokio::sync::oneshot::channel::<String>();
                        
                        // Send request to middleware handler
                        let req = crate::types::MiddlewareRequest {
                            hop_json: json_str.clone(),
                            response_tx,
                        };
                        
                        if mw_tx.send(req).is_err() {
                            eprintln!("[DEBUG handler] Middleware channel closed, using original");
                            let _ = ws_writer_clone.send(Message::Text(json_str)).await;
                            continue;
                        }
                        
                        eprintln!("[DEBUG handler] Waiting for enriched data...");
                        
                        // Wait for enriched data
                        match response_rx.await {
                            Ok(enriched) => {
                                eprintln!("[DEBUG handler] Got enriched data");
                                let _ = ws_writer_clone.send(Message::Text(enriched)).await;
                            }
                            Err(_) => {
                                eprintln!("[DEBUG handler] Middleware response failed, using original");
                                let _ = ws_writer_clone.send(Message::Text(json_str)).await;
                            }
                        }
                    } else {
                        // No middleware, send original
                        eprintln!("[DEBUG handler] No middleware, sending original");
                        let json_str = serde_json::to_string(&hop_msg).unwrap();
                        let _ = ws_writer_clone.send(Message::Text(json_str)).await;
                    }
                }
                ws_writer_clone
            })
        };
        
        // Get the fd values from the Arc/Mutex
        let raw_fd = match *raw_fd_arc.lock().unwrap() {
            Some(fd) => fd,
            None => {
                eprintln!("[DEBUG handler] Raw socket already closed");
                return;
            }
        };
        let icmp_fd = match *icmp_fd_arc.lock().unwrap() {
            Some(fd) => fd,
            None => {
                eprintln!("[DEBUG handler] ICMP socket already closed");
                return;
            }
        };
        
        eprintln!("[DEBUG handler] === 0trace: Sending ALL probes (TTL 1-{}) ===", max_hops);        // STEP 1: Send all probe packets at once (0trace technique)
        for ttl in 1..=max_hops {
            let seq = seq_base.wrapping_add(ttl as u32);
            let send_at = tokio::time::Instant::now();
            
            match send_tcp_probe(
                raw_fd,
                trace_params.0,   // src_ip (our server)
                trace_params.2,   // dst_ip (real client)
                trace_params.1,   // src_port
                trace_params.3,   // dst_port
                seq,
                ttl,
            ) {
                Ok(ip_id) => {
                    probe_map.insert(ip_id, (ttl, send_at));
                    eprintln!("[DEBUG handler] Sent probe TTL={}, IP_ID={}", ttl, ip_id);
                }
                Err(e) => {
                    eprintln!("[DEBUG handler] Failed to send probe TTL={}: {}", ttl, e);
                }
            }
            
            // Small delay between sends to avoid overwhelming the network
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
        
        eprintln!("[DEBUG handler] === All {} probes sent, collecting ICMP responses ===", probe_map.len());
        
        // STEP 2: Collect ICMP responses for all probes (true 0trace approach)
        // We read ICMP packets and check if they match ANY of our expected IP IDs
        let collection_deadline = tokio::time::Instant::now() + ttl_timeout * 3;
        let total_probes = probe_map.len();
        
        while !probe_map.is_empty() && tokio::time::Instant::now() < collection_deadline {
            // Build map of all IP IDs -> TTL we're still waiting for
            let expected_ids: std::collections::HashMap<u16, u8> = probe_map
                .iter()
                .map(|(ip_id, (ttl, _))| (*ip_id, *ttl))
                .collect();
            
            let remaining_time_ms = collection_deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(500) as u64; // Check every 500ms max
            
            if remaining_time_ms == 0 {
                break;
            }
            
            // Poll for ANY ICMP response matching our probes
            match poll_icmp_any(icmp_fd, &expected_ids, remaining_time_ms).await {
                Ok(Some((ip_id, hop_info))) => {
                    // Found a response! Remove from pending and report
                    if let Some((ttl, send_at)) = probe_map.remove(&ip_id) {
                        let rtt_ms = send_at.elapsed().as_secs_f64() * 1000.0;
                        eprintln!("[DEBUG handler] Got response for TTL={}: router {}, RTT: {:.2}ms ({}/{} responses)", 
                            ttl, hop_info.router_ip, rtt_ms, total_probes - probe_map.len(), total_probes);
                        
                        // Prepare modifications for JSON (only if any were detected)
                        let modifications_opt = if hop_info.modifications.ttl_modified 
                            || hop_info.modifications.flags_modified 
                            || hop_info.modifications.options_stripped 
                            || hop_info.modifications.tcp_flags_modified 
                            || !hop_info.modifications.modifications.is_empty() {
                            Some(hop_info.modifications.clone())
                        } else {
                            None
                        };
                        
                        let hop = Hop {
                            client_id: peer_id_clone.clone(),
                            ttl,
                            router: hop_info.router_ip.clone(),
                            rtt_ms,
                            modifications: modifications_opt.clone(),
                        };
                        let payload = serde_json::to_value(&hop).unwrap();
                        event_bus().emit("hop", &payload);
                        
                        // Send hop to client with MPLS labels and packet modifications
                        let mpls_json: Vec<serde_json::Value> = hop_info.mpls_labels.iter().map(|l| {
                            serde_json::json!({
                                "label": l.label,
                                "exp": l.exp,
                                "ttl": l.ttl
                            })
                        }).collect();
                        
                        let modifications_json = if let Some(ref mods) = modifications_opt {
                            serde_json::json!({
                                "ttl_modified": mods.ttl_modified,
                                "flags_modified": mods.flags_modified,
                                "options_stripped": mods.options_stripped,
                                "tcp_flags_modified": mods.tcp_flags_modified,
                                "modifications": mods.modifications
                            })
                        } else {
                            serde_json::Value::Null
                        };
                        
                        let hop_msg = serde_json::json!({
                            "type": "hop",
                            "clientId": peer_id_clone.clone(),
                            "ttl": ttl,
                            "ip": hop_info.router_ip,
                            "router": hop_info.router_ip,
                            "rtt_ms": rtt_ms,
                            "mpls": mpls_json,
                            "modifications": modifications_json
                        });
                        
                        // Queue the hop message for middleware processing
                        eprintln!("[DEBUG handler] Queueing hop for middleware: TTL={}", ttl);
                        let _ = hop_tx.send(hop_msg);
                    }
                }
                Ok(None) => {
                    // Timeout, no ICMP received in this iteration
                    eprintln!("[DEBUG handler] No ICMP received in this iteration, {} probes still pending", probe_map.len());
                }
                Err(e) => {
                    eprintln!("[DEBUG handler] Error polling ICMP: {}", e);
                }
            }
        }
        
        // Report any probes that never got a response
        for (_ip_id, (ttl, _)) in probe_map {
            eprintln!("[DEBUG handler] Timeout for TTL={}", ttl);
            let timeout_msg = serde_json::json!({
                "type": "hop",
                "ttl": ttl,
                "timeout": true
            });
            let _ = hop_tx.send(timeout_msg);
        }

        // Close the hop queue - no more hops will be sent
        drop(hop_tx);
        
        // Wait for middleware task to finish processing all queued hops
        let mut ws_writer = middleware_task.await.unwrap();
        
        let _ = ws_writer
            .send(Message::Text(r#"{"type":"clientDone","message":"zerotrace done"}"#.into()))
            .await;
        
        // Clean up sockets - take ownership from Arc to ensure proper cleanup
        if let Some(fd) = raw_fd_arc.lock().unwrap().take() {
            unsafe { libc::close(fd); }
            eprintln!("[DEBUG handler] Closed raw socket");
        }
        if let Some(fd) = icmp_fd_arc.lock().unwrap().take() {
            unsafe { libc::close(fd); }
            eprintln!("[DEBUG handler] Closed ICMP socket");
        }
        
        let _ = done_tx.send(());
    });

    // Wait for client to send start message with target
    let read_task = tokio::spawn(async move {
        while let Some(msg) = ws_reader.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    eprintln!("[DEBUG handler] Received message: {}", text);
                    // Expected format: {"target":"8.8.8.8","port":80}
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let (Some(target), Some(port)) = (json.get("target"), json.get("port")) {
                            if let (Some(target_str), Some(port_num)) = (target.as_str(), port.as_u64()) {
                                eprintln!("[DEBUG handler] Got target: {}:{}", target_str, port_num);
                                // TODO: Send this to trace_task via channel
                            }
                        }
                    }
                }
                Ok(Message::Pong(_)) => {
                    // ignore; tungstenite handles pings/pongs
                }
                Ok(Message::Close(_)) => break,
                Ok(_other) => { /* ignore */ }
                Err(_e) => break,
            }
        }
    });

    let _ = done_rx.await;
    let _ = trace_task.await;
    let _ = read_task.await;

    // Final cleanup - ensure sockets are closed even if tasks failed
    if let Some(fd) = raw_fd_cleanup.lock().unwrap().take() {
        unsafe { libc::close(fd); }
        eprintln!("[DEBUG handler] Final cleanup: closed raw socket");
    }
    if let Some(fd) = icmp_fd_cleanup.lock().unwrap().take() {
        unsafe { libc::close(fd); }
        eprintln!("[DEBUG handler] Final cleanup: closed ICMP socket");
    }

    event_bus().emit("clientDone", &serde_json::json!({ "clientId": peer_id }));
}
