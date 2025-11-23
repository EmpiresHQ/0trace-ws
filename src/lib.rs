#![cfg(target_os = "linux")] // Linux-only (IP_RECVERR/MSG_ERRQUEUE)

//! ZeroTrace WebSocket Server
//!
//! A WebSocket server with network traceroute capabilities.
//! Uses Linux-specific features to capture ICMP Time Exceeded messages
//! and trace the network path to each connected client.

mod events;
mod handler;
mod socket;
mod socket2;
mod types;

use napi_derive::napi;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::Duration;

// Re-export public types
pub use types::{ServerHandle, ServerOptions};

// ------------- N-API entry: start_server ---------------------


#[napi]
pub fn start_server(opts: ServerOptions) -> napi::Result<ServerHandle> {
    let host = opts.host.unwrap_or_else(|| "0.0.0.0".into());
    let port = opts.port;
    let max_hops = opts.max_hops.unwrap_or(30);
    let per_ttl = opts.per_ttl_timeout_ms.unwrap_or(1200);

    // Dedicated Tokio runtime for the server
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| napi::Error::from_reason(format!("tokio runtime: {}", e)))?;

    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let ctl = types::ServerCtl {
        shutdown_tx: shutdown_tx.clone(),
    };

    rt.spawn(async move {
        let addr = format!("{}:{}", host, port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                events::event_bus().emit(
                    "error",
                    &serde_json::json!({"message": format!("bind failed: {}", e)}),
                );
                return;
            }
        };

        events::event_bus().emit(
            "clientConnected",
            &serde_json::json!({"message": format!("listening on {}", addr)}),
        );

        let mut shutdown_rx = shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    events::event_bus().emit(
                        "clientDone",
                        &serde_json::json!({"message": "server stopping"}),
                    );
                    break;
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, peer)) => {
                            tokio::spawn(handler::handle_client(
                                stream,
                                peer,
                                max_hops as u8,
                                Duration::from_millis(per_ttl as u64),
                            ));
                        }
                        Err(e) => {
                            events::event_bus().emit(
                                "error",
                                &serde_json::json!({"message": format!("accept failed: {}", e)}),
                            );
                        }
                    }
                }
            }
        }
    });

    Ok(ServerHandle { rt, ctl })
}

// ------------- Unit Tests --------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hop;

    #[test]
    fn test_hop_serialization() {
        let hop = Hop {
            client_id: "127.0.0.1:12345".to_string(),
            ttl: 5,
            router: "192.168.1.1".to_string(),
            rtt_ms: 12.34,
        };

        let json = serde_json::to_string(&hop).unwrap();
        assert!(json.contains("clientId"));
        assert!(json.contains("127.0.0.1:12345"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_server_options_defaults() {
        let opts = ServerOptions {
            host: None,
            port: 8080,
            max_hops: None,
            per_ttl_timeout_ms: None,
            iface_hint: None,
        };

        let host = opts.host.unwrap_or_else(|| "0.0.0.0".into());
        let max_hops = opts.max_hops.unwrap_or(30);
        let per_ttl = opts.per_ttl_timeout_ms.unwrap_or(1200);

        assert_eq!(host, "0.0.0.0");
        assert_eq!(max_hops, 30);
        assert_eq!(per_ttl, 1200);
    }

    #[test]
    fn test_hop_ttl_range() {
        for ttl in 1..=255 {
            let hop = Hop {
                client_id: "test".to_string(),
                ttl,
                router: "10.0.0.1".to_string(),
                rtt_ms: 1.0,
            };
            assert!(hop.ttl > 0);
        }
    }
}
