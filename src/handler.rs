use crate::events::event_bus;
use crate::socket2::{create_raw_socket, create_icmp_socket, poll_icmp_socket, send_tcp_probe};
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

    // Do WebSocket handshake
    let cb = |_req: &Request,
              mut resp: Response|
     -> Result<Response, ErrorResponse> {
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
    
    // Get local and remote addresses for the TCP connection
    // These will be used to craft probe packets that look like they're part
    // of the real connection (same src/dst IP:port)
    let (local_addr, remote_addr) = unsafe {
        let mut local: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        libc::getsockname(tcp_fd, &mut local as *mut _ as *mut libc::sockaddr, &mut local_len);
        
        let local_in = &*((&local) as *const _ as *const libc::sockaddr_in);
        let local_ip = Ipv4Addr::from(u32::from_be(local_in.sin_addr.s_addr));
        let local_port = u16::from_be(local_in.sin_port);
        
        let _remote_ip = match peer.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => {
                eprintln!("[DEBUG handler] IPv6 not supported");
                return;
            }
        };
        
        // For now, hardcode target to 8.8.8.8:80 (Google DNS) for testing
        // TODO: Accept target from WebSocket message
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);
        let target_port = 80;
        
        ((local_ip, local_port), (target_ip, target_port))
    };
    
    eprintln!("[DEBUG handler] Connection: {}:{} -> {}:{}", 
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

    // Tracing task
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let peer_id_clone = peer_id.clone();
    
    // Generate a base TCP sequence number for our probe packets
    // Each TTL will use seq_base + ttl to make packets unique
    let seq_base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() & 0xFFFFFFFF) as u32;

    let trace_task = tokio::spawn(async move {
        // Send a greeting
        let _ = ws_writer
            .send(Message::Text(r#"{"type":"connected","message":"zerotrace connected"}"#.into()))
            .await;

        // Traceroute: increment TTL from 1 to max_hops
        // Each iteration sends a probe packet and waits for ICMP response
        for ttl in 1..=max_hops {
            eprintln!("[DEBUG handler] === Starting hop TTL={} ===", ttl);
            
            // Send a crafted TCP packet with the current TTL
            // The packet mimics the real connection (same src/dst IP:port)
            // but has a low TTL that will expire at the target hop
            let send_at = tokio::time::Instant::now();
            let seq = seq_base.wrapping_add(ttl as u32);
            
            eprintln!("[DEBUG handler] Sending raw TCP probe for TTL={}", ttl);
            
            // send_tcp_probe crafts a complete IP + TCP packet with:
            // - Custom TTL (will expire at router #ttl)
            // - Source/dest matching the real WebSocket connection
            // - Unique IP ID for packet identification
            let ip_id = match send_tcp_probe(
                raw_fd,
                local_addr.0,
                remote_addr.0,
                local_addr.1,
                remote_addr.1,
                seq,
                ttl,
            ) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("[DEBUG handler] Failed to send probe: {}", e);
                    event_bus().emit(
                        "error",
                        &serde_json::json!({"clientId": peer_id_clone, "message": format!("send probe failed: {}", e)}),
                    );
                    break;
                }
            };
            
            eprintln!("[DEBUG handler] Probe sent (IP ID={}), waiting for ICMP response...", ip_id);

            // Poll the ICMP socket for Time Exceeded messages
            // The ICMP socket receives all ICMP packets; we filter by IP ID
            // to match responses to our specific probe packet
            match timeout(ttl_timeout, async move { poll_icmp_socket(icmp_fd, ip_id).await }).await {
                Ok(Ok(Some(router))) => {
                    let rtt_ms = send_at.elapsed().as_secs_f64() * 1000.0;
                    eprintln!("[DEBUG handler] Got router IP: {}, RTT: {:.2}ms", router, rtt_ms);
                    let hop = Hop {
                        client_id: peer_id_clone.clone(),
                        ttl,
                        router: router.clone(),
                        rtt_ms,
                    };
                    let payload = serde_json::to_value(&hop).unwrap();
                    event_bus().emit("hop", &payload);
                    // Send hop to client with type field
                    let hop_msg = serde_json::json!({
                        "type": "hop",
                        "clientId": peer_id_clone.clone(),
                        "ttl": ttl,
                        "ip": router.clone(),
                        "router": router.clone(),
                        "rtt_ms": rtt_ms
                    });
                    let _ = ws_writer
                        .send(Message::Text(serde_json::to_string(&hop_msg).unwrap()))
                        .await;
                }
                Ok(Ok(None)) => {
                    eprintln!("[DEBUG handler] No ICMP response (poll_icmp_socket returned None)");
                    // No ICMP response - could mean:
                    // - Router doesn't send ICMP (filtered/configured not to)
                    // - We reached the destination (no TTL expiry)
                    // - Packet was lost
                    let _ = ws_writer
                        .send(Message::Text(format!(
                            r#"{{"type":"hop","ttl":{},"note":"no-icmp"}}"#,
                            ttl
                        )))
                        .await;
                }
                Ok(Err(e)) => {
                    eprintln!("[DEBUG handler] Error reading errqueue: {}", e);
                    event_bus().emit(
                        "error",
                        &serde_json::json!({"clientId": peer_id_clone, "message": format!("errqueue read error: {}", e)}),
                    );
                    break;
                }
                Err(_) => {
                    eprintln!("[DEBUG handler] Timeout waiting for ICMP");
                    // Timeout - router didn't respond in time
                    let _ = ws_writer
                        .send(Message::Text(format!(
                            r#"{{"type":"hop","ttl":{},"timeout":true}}"#,
                            ttl
                        )))
                        .await;
                }
            }
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
