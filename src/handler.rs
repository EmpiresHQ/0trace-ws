use crate::events::event_bus;
use crate::socket::{create_raw_socket, create_icmp_socket, poll_icmp_socket, send_tcp_probe};
use crate::types::Hop;
use futures::{SinkExt, StreamExt};
use std::net::{SocketAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};
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
    // We need: local IP:port and remote IP:port to craft realistic TCP packets
    let tcp = ws.get_ref();
    let tcp_fd = tcp.as_raw_fd();
    
    // Get local (server) address and remote (client after NAT) address
    // We'll trace the path FROM our server TO the client
    let (local_addr, remote_addr) = unsafe {
        let mut local: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        libc::getsockname(tcp_fd, &mut local as *mut _ as *mut libc::sockaddr, &mut local_len);
        
        let local_in = &*((&local) as *const _ as *const libc::sockaddr_in);
        let local_ip = Ipv4Addr::from(u32::from_be(local_in.sin_addr.s_addr));
        let local_port = u16::from_be(local_in.sin_port);
        
        // ALWAYS use real client IP from headers (required behind proxy like Traefik)
        let remote_ip = if let Some(real_ip) = *real_client_ip.lock().unwrap() {
            eprintln!("[DEBUG handler] Using real client IP from headers: {}", real_ip);
            real_ip
        } else {
            eprintln!("[DEBUG handler] No X-Forwarded-For or X-Real-IP header found!");
            match peer.ip() {
                std::net::IpAddr::V4(ip) => {
                    eprintln!("[DEBUG handler] Falling back to peer IP: {} (WARNING: this is likely the proxy!)", ip);
                    ip
                },
                _ => {
                    eprintln!("[DEBUG handler] IPv6 not supported");
                    return;
                }
            }
        };
        
        // For traceroute, we use arbitrary port (doesn't matter much)
        // The important part is the IP address
        let remote_port = 80;
        
        ((local_ip, local_port), (remote_ip, remote_port))
    };
    
    eprintln!("[DEBUG handler] Tracing path: Server {}:{} -> Client {}:{}", 
        local_addr.0, local_addr.1, remote_addr.0, remote_addr.1);

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
    let icmp_fd = match create_icmp_socket(Some(local_addr.0)) {
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

    // Split WebSocket so we can send/receive
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Send greeting
    let _ = ws_writer
        .send(Message::Text(r#"{"type":"connected","message":"Trace started automatically"}"#.into()))
        .await;

    // 0trace approach: Send ALL probe packets immediately, then collect ICMP responses
    // This is the key difference from traditional traceroute which sends one packet,
    // waits for response, then sends the next one
    
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let peer_id_clone = peer_id.clone();
    
    // Generate a base TCP sequence number for our probe packets
    let seq_base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() & 0xFFFFFFFF) as u32;

    let trace_task = tokio::spawn(async move {
        // Map to track IP IDs -> (TTL, send_time)
        let mut probe_map = std::collections::HashMap::new();
        
        eprintln!("[DEBUG handler] === 0trace: Sending ALL probes (TTL 1-{}) ===", max_hops);
        
        // STEP 1: Send all probe packets at once (0trace technique)
        for ttl in 1..=max_hops {
            let seq = seq_base.wrapping_add(ttl as u32);
            let send_at = tokio::time::Instant::now();
            
            match send_tcp_probe(
                raw_fd,
                local_addr.0,   // src_ip (our server)
                remote_addr.0,  // dst_ip (client)
                local_addr.1,   // src_port
                remote_addr.1,  // dst_port
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
        
        // STEP 2: Collect ICMP responses for all probes
        // We listen for ICMP Time Exceeded messages and match them by IP ID
        let collection_deadline = tokio::time::Instant::now() + ttl_timeout * 3;
        let total_probes = probe_map.len();
        
        // We need to poll for ANY ICMP response, not specific IP IDs
        // Use a loop that receives any ICMP packet and checks if it matches any of our probes
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100; // Prevent infinite loop
        
        while !probe_map.is_empty() && tokio::time::Instant::now() < collection_deadline && attempts < MAX_ATTEMPTS {
            attempts += 1;
            
            // Receive ANY ICMP packet with a short timeout
            // We'll use poll_icmp_socket in a special way - try each IP ID we're waiting for
            // But actually we need to modify poll_icmp_socket to accept ANY matching packet
            
            // For now, iterate through all pending IP IDs and check each one with a very short timeout
            let mut found_any = false;
            let check_timeout = Duration::from_millis(50);
            
            for (&ip_id, &(ttl, send_at)) in probe_map.clone().iter() {
                match timeout(check_timeout, poll_icmp_socket(icmp_fd, ip_id)).await {
                    Ok(Ok(Some(hop_info))) => {
                        found_any = true;
                        probe_map.remove(&ip_id);
                        
                        let rtt_ms = send_at.elapsed().as_secs_f64() * 1000.0;
                        eprintln!("[DEBUG handler] Got response for TTL={}: router {}, RTT: {:.2}ms ({}/{} responses)", 
                            ttl, hop_info.router_ip, rtt_ms, total_probes - probe_map.len(), total_probes);
                        
                        let hop = Hop {
                            client_id: peer_id_clone.clone(),
                            ttl,
                            router: hop_info.router_ip.clone(),
                            rtt_ms,
                        };
                        let payload = serde_json::to_value(&hop).unwrap();
                        event_bus().emit("hop", &payload);
                        
                        // Send hop to client with MPLS labels
                        let mpls_json: Vec<serde_json::Value> = hop_info.mpls_labels.iter().map(|l| {
                            serde_json::json!({
                                "label": l.label,
                                "exp": l.exp,
                                "ttl": l.ttl
                            })
                        }).collect();
                        
                        let hop_msg = serde_json::json!({
                            "type": "hop",
                            "clientId": peer_id_clone.clone(),
                            "ttl": ttl,
                            "ip": hop_info.router_ip,
                            "router": hop_info.router_ip,
                            "rtt_ms": rtt_ms,
                            "mpls": mpls_json
                        });
                        let _ = ws_writer
                            .send(Message::Text(serde_json::to_string(&hop_msg).unwrap()))
                            .await;
                        
                        break; // Found one, continue outer loop
                    }
                    Ok(Ok(None)) | Err(_) => {
                        // No response yet for this IP ID, continue checking others
                        continue;
                    }
                    Ok(Err(_e)) => {
                        // Error for this probe, skip it
                        continue;
                    }
                }
            }
            
            // If we didn't find any responses in this iteration, wait a bit before trying again
            if !found_any {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        // Report any probes that never got a response
        for (_ip_id, (ttl, _)) in probe_map {
            eprintln!("[DEBUG handler] Timeout for TTL={}", ttl);
            let _ = ws_writer
                .send(Message::Text(format!(
                    r#"{{"type":"hop","ttl":{},"timeout":true}}"#,
                    ttl
                )))
                .await;
        }

        let _ = ws_writer
            .send(Message::Text(r#"{"type":"clientDone","message":"zerotrace done"}"#.into()))
            .await;
        
        // Clean up sockets
        unsafe { 
            libc::close(raw_fd);
            libc::close(icmp_fd);
        };
        eprintln!("[DEBUG handler] Closed raw and ICMP sockets");
        
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

    event_bus().emit("clientDone", &serde_json::json!({ "clientId": peer_id }));
}
