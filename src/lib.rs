#![cfg(target_os = "linux")] // Linux-only (IP_RECVERR/MSG_ERRQUEUE)

//! ZeroTrace WebSocket Server
//!
//! A WebSocket server with network traceroute capabilities.
//! Uses Linux-specific features to capture ICMP Time Exceeded messages
//! and trace the network path to each connected client.

mod constants;
mod events;
mod handler;
mod types;
mod packet;
mod icmp;
mod network;
mod connection;

use napi_derive::napi;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::Duration;

// Re-export public types
pub use types::{Server, ServerOptions};

// ------------- N-API entry: start_server ---------------------

#[napi]
pub fn start_server(opts: ServerOptions) -> napi::Result<Server> {
    let host = opts.host.unwrap_or_else(|| constants::DEFAULT_BIND_HOST.into());
    let port = opts.port;
    let max_hops = opts.max_hops.unwrap_or(constants::DEFAULT_MAX_HOPS);
    let per_ttl = opts.per_ttl_timeout_ms.unwrap_or(constants::DEFAULT_PER_TTL_TIMEOUT_MS);

    // Convert middleware JsFunction to ThreadsafeFunction if provided
    let middleware_tsfn = if let Some(middleware_fn) = opts.middleware {
        eprintln!("[DEBUG] Creating ThreadsafeFunction for middleware");
        Some(middleware_fn.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(String, tokio::sync::mpsc::UnboundedSender<String>)>| {
                eprintln!("[DEBUG] TSFN callback executing in JS context");
                let (hop_json, result_tx) = ctx.value;
                
                // Parse JSON string to object
                let global = ctx.env.get_global()?;
                let json_obj: napi::JsObject = global.get_named_property("JSON")?;
                let json_parse: napi::JsFunction = json_obj.get_named_property("parse")?;
                let json_str = ctx.env.create_string(&hop_json)?;
                let hop_obj: napi::JsUnknown = json_parse.call(None, &[json_str])?;
                
                // Wrap result_tx in Arc so it can be cloned into the closure
                let result_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(result_tx)));
                
                // Create callback function (next) that JS will call with enriched data
                let next_callback = ctx.env.create_function_from_closure("next", move |ctx| {
                    eprintln!("[DEBUG] next() callback called from JS");
                    let enriched_json: String = ctx.get::<napi::JsString>(0)?.into_utf8()?.as_str()?.to_string();
                    eprintln!("[DEBUG] Sending enriched data back to Rust: {}", &enriched_json[..enriched_json.len().min(50)]);
                    
                    // Send enriched data back to Rust
                    if let Some(tx) = result_tx.lock().unwrap().take() {
                        let _ = tx.send(enriched_json);
                    } else {
                        eprintln!("[DEBUG] next() called multiple times - ignoring");
                    }
                    
                    ctx.env.get_undefined()
                })?;
                
                eprintln!("[DEBUG] Calling JS middleware with hop and next callback");
                
                // Return [hopObj, nextCallback] so middleware can be called as: middleware(hopObj, next)
                Ok(vec![hop_obj, next_callback.into_unknown()])
            },
        )?)
    } else {
        eprintln!("[DEBUG] No middleware provided");
        None
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let server_task = types::ServerTask {
        host,
        port,
        max_hops,
        per_ttl,
        shutdown_tx: shutdown_tx.clone(),
        middleware_tsfn,
    };

    Ok(Server { 
        task: std::sync::Arc::new(std::sync::Mutex::new(Some(server_task))),
        shutdown_tx,
    })
}

pub(crate) async fn run_server_loop(
    host: String,
    port: u16,
    max_hops: u32,
    per_ttl: u32,
    shutdown_tx: broadcast::Sender<()>,
    middleware_tsfn: Option<napi::threadsafe_function::ThreadsafeFunction<(String, tokio::sync::mpsc::UnboundedSender<String>), napi::threadsafe_function::ErrorStrategy::Fatal>>,
) {
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

    // Create middleware channel if middleware is provided
    let middleware_channel = if let Some(tsfn) = middleware_tsfn {
        let (middleware_tx, mut middleware_rx) = tokio::sync::mpsc::unbounded_channel::<(
            String,
            tokio::sync::mpsc::UnboundedSender<String>,
        )>();

        // Spawn task to process middleware requests
        tokio::spawn(async move {
            eprintln!("[DEBUG] Middleware handler task started");
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                eprintln!("[DEBUG] Middleware request: {}", &json_str[..json_str.len().min(50)]);
                
                // Create channel for receiving result from JS
                let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                
                // Call TSFN with both the JSON and the result channel
                let call_status = tsfn.call(
                    (json_str.clone(), result_tx),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
                
                eprintln!("[DEBUG] TSFN call status: {:?}", call_status);
                
                // Wait for result from JS with timeout
                let promise_result = tokio::time::timeout(
                    std::time::Duration::from_millis(1000),  // Reduce timeout to 1s
                    result_rx.recv()
                ).await;
                
                match promise_result {
                    Ok(Some(enriched_json)) => {
                        eprintln!("[DEBUG] Got enriched result from JS: {}", &enriched_json[..enriched_json.len().min(50)]);
                        let _ = promise_tx.send(enriched_json);
                    }
                    Ok(None) => {
                        eprintln!("[DEBUG] Channel closed without result, using fallback");
                        let _ = promise_tx.send(json_str);
                    }
                    Err(_) => {
                        eprintln!("[DEBUG] Timeout waiting for JS middleware (1s), using fallback");
                        let _ = promise_tx.send(json_str);
                    }
                }
            }
            eprintln!("[DEBUG] Middleware handler task stopped");
        });

        Some(middleware_tx)
    } else {
        eprintln!("[DEBUG] No middleware provided");
        None
    };

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
                            middleware_channel.clone(),
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
            modifications: None,
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
            middleware: None,
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
                modifications: None,
            };
            assert!(hop.ttl > 0);
        }
    }
}
