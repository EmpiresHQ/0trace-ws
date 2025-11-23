use crate::events::event_bus;
use crate::socket::{create_raw_socket, enable_ip_recverr, poll_errqueue, send_tcp_probe};
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

    // Get TCP connection details
    let tcp = ws.get_ref();
    let tcp_fd = tcp.as_raw_fd();
    
    // Get local and remote addresses
    let (local_addr, remote_addr) = unsafe {
        let mut local: libc::sockaddr_storage = std::mem::zeroed();
        let mut local_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        libc::getsockname(tcp_fd, &mut local as *mut _ as *mut libc::sockaddr, &mut local_len);
        
        let local_in = &*((&local) as *const _ as *const libc::sockaddr_in);
        let local_ip = Ipv4Addr::from(u32::from_be(local_in.sin_addr.s_addr));
        let local_port = u16::from_be(local_in.sin_port);
        
        let remote_ip = match peer.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => {
                eprintln!("[DEBUG handler] IPv6 not supported");
                return;
            }
        };
        
        ((local_ip, local_port), (remote_ip, peer.port()))
    };
    
    eprintln!("[DEBUG handler] Connection: {}:{} -> {}:{}", 
        local_addr.0, local_addr.1, remote_addr.0, remote_addr.1);

    // Create raw socket for sending TCP probes
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

    // Enable IP_RECVERR on raw socket to receive ICMP errors
    if let Err(e) = enable_ip_recverr(raw_fd) {
        event_bus().emit(
            "error",
            &serde_json::json!({"clientId": peer_id, "message": format!("IP_RECVERR enable failed: {}", e)}),
        );
        unsafe { libc::close(raw_fd) };
        return;
    }

    // Split WebSocket so we can send/receive
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Tracing task
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let peer_id_clone = peer_id.clone();
    let seq_base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() & 0xFFFFFFFF) as u32;

    let trace_task = tokio::spawn(async move {
        // Send a greeting
        let _ = ws_writer
            .send(Message::Text(r#"{"type":"connected","message":"zerotrace connected"}"#.into()))
            .await;

        // Walk TTL from 1..=max_hops
        for ttl in 1..=max_hops {
            eprintln!("[DEBUG handler] === Starting hop TTL={} ===", ttl);
            
            // Send TCP probe packets with current TTL using raw socket
            let send_at = tokio::time::Instant::now();
            let seq = seq_base.wrapping_add(ttl as u32);
            
            eprintln!("[DEBUG handler] Sending raw TCP probe for TTL={}", ttl);
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

            // Poll kernel errqueue for Time Exceeded from the router for up to ttl_timeout
            match timeout(ttl_timeout, async move { poll_errqueue(raw_fd).await }).await {
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
                    eprintln!("[DEBUG handler] No ICMP response (poll_errqueue returned None)");
                    // No ICMP; maybe reached destination (no Time Exceeded), or filtered.
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
                    // timeout
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
        
        // Clean up raw socket
        unsafe { libc::close(raw_fd) };
        eprintln!("[DEBUG handler] Closed raw socket");
        
        let _ = done_tx.send(());
    });

    // Consume client messages (optional: keepalive / pong reading)
    let read_task = tokio::spawn(async move {
        while let Some(msg) = ws_reader.next().await {
            match msg {
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
