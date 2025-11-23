use crate::events::event_bus;
use crate::socket::{enable_ip_recverr, poll_errqueue, set_ip_ttl};
use crate::types::Hop;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
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

    // Grab the underlying TCP fd before splitting
    // We need to get the raw fd from the tokio TcpStream
    let tcp = ws.get_ref();
    let fd = tcp.as_raw_fd();

    // Split so we can send/receive
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Enable IP_RECVERR on this socket so ICMP Time Exceeded ends up in errqueue
    if let Err(e) = enable_ip_recverr(fd) {
        event_bus().emit(
            "error",
            &serde_json::json!({"clientId": peer_id, "message": format!("IP_RECVERR enable failed: {}", e)}),
        );
        // We proceed but will not get hop info
    }

    // Tracing task
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let peer_id_clone = peer_id.clone();

    let trace_task = tokio::spawn(async move {
        // Send a greeting
        let _ = ws_writer
            .send(Message::Text(r#"{"type":"connected","message":"zerotrace connected"}"#.into()))
            .await;

        // Walk TTL from 1..=max_hops
        for ttl in 1..=max_hops {
            eprintln!("[DEBUG handler] === Starting hop TTL={} ===", ttl);
            
            if let Err(e) = set_ip_ttl(fd, ttl as i32) {
                event_bus().emit(
                    "error",
                    &serde_json::json!({"clientId": peer_id_clone, "message": format!("set TTL {} failed: {}", ttl, e)}),
                );
                break;
            }

            // Send a tiny WS ping; this triggers one TCP segment at current TTL
            let send_at = tokio::time::Instant::now();
            eprintln!("[DEBUG handler] Sending WebSocket ping with payload [{}]", ttl);
            if let Err(e) = ws_writer.send(Message::Ping(vec![ttl])).await {
                event_bus().emit(
                    "error",
                    &serde_json::json!({"clientId": peer_id_clone, "message": format!("send ping failed: {}", e)}),
                );
                break;
            }
            
            // CRITICAL: Flush to ensure the packet is actually sent NOW
            if let Err(e) = ws_writer.flush().await {
                event_bus().emit(
                    "error",
                    &serde_json::json!({"clientId": peer_id_clone, "message": format!("flush failed: {}", e)}),
                );
                break;
            }
            eprintln!("[DEBUG handler] Ping sent and flushed, waiting for ICMP response...");

            // Poll kernel errqueue for Time Exceeded from the router for up to ttl_timeout
            match timeout(ttl_timeout, async move { poll_errqueue(fd).await }).await {
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
