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

/// Handle middleware request in JS thread
/// Calls the middleware function, awaits the Promise, and sends result back
fn handle_middleware_request(
    ctx: napi::threadsafe_function::ThreadSafeCallContext<types::MiddlewareRequest>,
) -> napi::Result<Vec<napi::JsUnknown>> {
    eprintln!("[DEBUG lib] Middleware TSFN called");
    let req = ctx.value;
    let hop_json = req.hop_json.clone();
    let ws_tx = req.ws_tx;
    
    // Parse JSON to object
    let global = ctx.env.get_global()?;
    let json_obj: napi::JsObject = global.get_named_property("JSON")?;
    let json_parse: napi::JsFunction = json_obj.get_named_property("parse")?;
    let json_str = ctx.env.create_string(&hop_json)?;
    let hop_obj: napi::JsUnknown = json_parse.call(None, &[json_str])?;
    
    // Get middleware from global scope (костыль, но работает)
    let middleware_fn: napi::JsFunction = match global.get_named_property("__zerotrace_middleware") {
        Ok(f) => {
            eprintln!("[DEBUG lib] Found __zerotrace_middleware in global");
            f
        }
        Err(e) => {
            eprintln!("[DEBUG lib] ERROR: Failed to get __zerotrace_middleware: {:?}", e);
            eprintln!("[DEBUG lib] Sending original data");
            let _ = ws_tx.send(hop_json);
            return Ok(vec![ctx.env.get_undefined()?.into_unknown()]);
        }
    };
    
    // Call middleware with hop object - it returns Promise<String>
    eprintln!("[DEBUG lib] Calling middleware function...");
    let promise_result = match middleware_fn.call(None, &[hop_obj]) {
        Ok(r) => {
            eprintln!("[DEBUG lib] Middleware function called successfully");
            r
        }
        Err(e) => {
            eprintln!("[DEBUG lib] ERROR: Failed to call middleware: {:?}", e);
            eprintln!("[DEBUG lib] Sending original data");
            let _ = ws_tx.send(hop_json);
            return Ok(vec![ctx.env.get_undefined()?.into_unknown()]);
        }
    };
    
    // Convert to Promise<String>
    use napi::bindgen_prelude::*;
    use napi::NapiRaw;
    let promise = unsafe {
        Promise::<String>::from_napi_value(ctx.env.raw(), NapiRaw::raw(&promise_result))?
    };
    
    eprintln!("[DEBUG lib] Got Promise<String>, spawning tokio task to await");
    
    // Promise<T> is Send, so we can pass it directly to tokio::spawn
    tokio::spawn(async move {
        eprintln!("[DEBUG lib] Awaiting Promise...");
        
        match promise.await {
            Ok(enriched_json) => {
                eprintln!("[DEBUG lib] Promise resolved! Got: {}", enriched_json);
                match ws_tx.send(enriched_json.clone()) {
                    Ok(_) => eprintln!("[DEBUG lib] Successfully sent to ws_tx channel"),
                    Err(e) => eprintln!("[DEBUG lib] ERROR: Failed to send to ws_tx: {:?}", e),
                }
            }
            Err(e) => {
                eprintln!("[DEBUG lib] Promise rejected: {:?}, sending original", e);
                match ws_tx.send(hop_json.clone()) {
                    Ok(_) => eprintln!("[DEBUG lib] Successfully sent original to ws_tx"),
                    Err(e) => eprintln!("[DEBUG lib] ERROR: Failed to send original: {:?}", e),
                }
            }
        }
    });
    
    Ok(vec![ctx.env.get_undefined()?.into_unknown()])
}

#[napi]
pub fn start_server(opts: ServerOptions) -> napi::Result<Server> {
    let host = opts.host.unwrap_or_else(|| "0.0.0.0".into());
    let port = opts.port;
    let max_hops = opts.max_hops.unwrap_or(30);
    let per_ttl = opts.per_ttl_timeout_ms.unwrap_or(1200);

    // Create channel for middleware requests if middleware provided
    let middleware_tx = if let Some(js_fn) = opts.middleware {
        eprintln!("[DEBUG lib] Setting up middleware channel");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<types::MiddlewareRequest>();
        
        // Create threadsafe function to call middleware
        let tsfn = js_fn.create_threadsafe_function(0, handle_middleware_request)?;
        
        // Spawn task to forward requests from channel to TSFN
        std::thread::spawn(move || {
            eprintln!("[DEBUG lib] Middleware forwarder thread started");
            loop {
                match rx.blocking_recv() {
                    Some(req) => {
                        eprintln!("[DEBUG lib] Forwarding middleware request");
                        use napi::threadsafe_function::{ThreadsafeFunction as TSF, ThreadsafeFunctionCallMode, ErrorStrategy};
                        TSF::<_, ErrorStrategy::Fatal>::call(&tsfn, req, ThreadsafeFunctionCallMode::NonBlocking);
                    }
                    None => {
                        eprintln!("[DEBUG lib] Middleware channel closed");
                        break;
                    }
                }
            }
        });
        
        Some(tx)
    } else {
        eprintln!("[DEBUG lib] No middleware provided");
        None
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let server_task = types::ServerTask {
        host,
        port,
        max_hops,
        per_ttl,
        shutdown_tx: shutdown_tx.clone(),
        middleware_tx,
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
    middleware_tx: Option<tokio::sync::mpsc::UnboundedSender<types::MiddlewareRequest>>,
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
                        let middleware_tx_clone = middleware_tx.clone();
                        tokio::spawn(handler::handle_client(
                            stream,
                            peer,
                            max_hops as u8,
                            Duration::from_millis(per_ttl as u64),
                            middleware_tx_clone,
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
