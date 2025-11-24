#![cfg(target_os = "linux")] // Linux-only (IP_RECVERR/MSG_ERRQUEUE)

//! ZeroTrace WebSocket Server
//!
//! A WebSocket server with network traceroute capabilities.
//! Uses Linux-specific features to capture ICMP Time Exceeded messages
//! and trace the network path to each connected client.

mod events;
mod handler;
mod socket;
mod types;

use napi_derive::napi;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::Duration;

// Re-export public types
pub use types::{Server, ServerOptions};

// ------------- N-API entry: start_server ---------------------


#[napi]
pub fn start_server(opts: ServerOptions) -> napi::Result<Server> {
    let host = opts.host.unwrap_or_else(|| "0.0.0.0".into());
    let port = opts.port;
    let max_hops = opts.max_hops.unwrap_or(30);
    let per_ttl = opts.per_ttl_timeout_ms.unwrap_or(1200);

    // Create threadsafe middleware function if provided
    let middleware = if let Some(js_fn) = opts.middleware {
        Some(js_fn.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<types::MiddlewareContext>| {
                let json_data = ctx.value.json_data;
                let sender = ctx.value.sender;
                
                // Parse JSON to object for JS using JSON.parse
                let global = ctx.env.get_global()?;
                let json_obj: napi::JsObject = global.get_named_property("JSON")?;
                let json_parse: napi::JsFunction = json_obj.get_named_property("parse")?;
                let json_str = ctx.env.create_string(&json_data)?;
                let hop_obj: napi::JsUnknown = json_parse.call(None, &[json_str])?;
                
                // Create next() callback function that receives object and converts back to JSON
                let next_fn = ctx.env.create_function_from_closure("next", move |ctx| {
                    let enriched_obj: napi::JsUnknown = ctx.get(0)?;
                    // Use JSON.stringify to convert object back to string
                    let global = ctx.env.get_global()?;
                    let json_obj: napi::JsObject = global.get_named_property("JSON")?;
                    let json_stringify: napi::JsFunction = json_obj.get_named_property("stringify")?;
                    let json_result_unknown: napi::JsUnknown = json_stringify.call(None, &[enriched_obj])?;
                    let json_result: napi::JsString = json_result_unknown.coerce_to_string()?;
                    let enriched_json = json_result.into_utf8()?.as_str()?.to_string();
                    if let Some(tx) = sender.lock().unwrap().take() {
                        let _ = tx.send(enriched_json);
                    }
                    ctx.env.get_undefined()
                })?;
                
                // Pass [hop_object, next_callback] to middleware
                Ok(vec![hop_obj, next_fn.into_unknown()])
            },
        )?)
    } else {
        None
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let server_task = types::ServerTask {
        host,
        port,
        max_hops,
        per_ttl,
        shutdown_tx: shutdown_tx.clone(),
        middleware,
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
    middleware: Option<types::MiddlewareFunction>,
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
                        let middleware_clone = middleware.clone();
                        tokio::spawn(handler::handle_client(
                            stream,
                            peer,
                            max_hops as u8,
                            Duration::from_millis(per_ttl as u64),
                            middleware_clone,
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
