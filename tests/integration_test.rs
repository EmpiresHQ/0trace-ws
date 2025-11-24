use napi::bindgen_prelude::*;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Mock data structure for testing
#[derive(Debug, Clone)]
struct MockHop {
    ttl: u8,
    ip: String,
    rtt_ms: f64,
}

/// Test middleware function that simulates JS callback
/// This will be called from Rust via ThreadsafeFunction
fn create_test_middleware(
    received_hops: Arc<Mutex<Vec<String>>>,
) -> impl Fn(String) -> Result<String> {
    move |json_str: String| {
        // Store received hop data
        received_hops.lock().unwrap().push(json_str.clone());
        
        // Parse and enrich (simulate GeoIP middleware)
        let mut hop: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| Error::from_reason(format!("JSON parse error: {}", e)))?;
        
        // Add mock GeoIP data
        if let Some(obj) = hop.as_object_mut() {
            obj.insert(
                "geo".to_string(),
                serde_json::json!({
                    "city": "Test City",
                    "country": "Test Country",
                    "latitude": 51.5074,
                    "longitude": -0.1278
                }),
            );
        }
        
        Ok(serde_json::to_string(&hop).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_chain() {
        // Test data
        let mock_hops = [
            MockHop {
                ttl: 1,
                ip: "192.168.1.1".to_string(),
                rtt_ms: 1.23,
            },
            MockHop {
                ttl: 2,
                ip: "10.0.0.1".to_string(),
                rtt_ms: 5.67,
            },
            MockHop {
                ttl: 3,
                ip: "8.8.8.8".to_string(),
                rtt_ms: 12.34,
            },
        ];

        // Storage for received hops
        let received_hops = Arc::new(Mutex::new(Vec::new()));
        let middleware = create_test_middleware(received_hops.clone());

        // Process each hop through middleware
        for hop in mock_hops.iter() {
            let hop_json = serde_json::json!({
                "type": "hop",
                "ttl": hop.ttl,
                "ip": hop.ip,
                "router": hop.ip,
                "rtt_ms": hop.rtt_ms,
            });

            let enriched = middleware(hop_json.to_string()).unwrap();
            let enriched_data: serde_json::Value = serde_json::from_str(&enriched).unwrap();

            // Verify enrichment
            assert!(enriched_data.get("geo").is_some());
            assert_eq!(enriched_data["ttl"], hop.ttl);
            assert_eq!(enriched_data["ip"], hop.ip);
            
            let geo = enriched_data["geo"].as_object().unwrap();
            assert_eq!(geo["city"], "Test City");
            assert_eq!(geo["country"], "Test Country");
        }

        // Verify all hops were processed
        assert_eq!(received_hops.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_middleware_async_flow() {
        // Simulate the async flow from spawn_middleware_processor_task
        
        // Create channels
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel::<serde_json::Value>();
        let (websocket_tx, mut websocket_rx) = mpsc::unbounded_channel::<String>();
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>, // Simplified: direct String instead of Promise
        )>();

        // Storage for verification
        let received_hops = Arc::new(Mutex::new(Vec::new()));
        let middleware_fn = create_test_middleware(received_hops.clone());

        // Spawn middleware processor (simulated)
        let middleware_tx_clone = middleware_tx.clone();
        let middleware_processor = tokio::spawn(async move {
            while let Some(hop_message) = hop_queue_rx.recv().await {
                let json_str = serde_json::to_string(&hop_message).unwrap();
                
                // Request processing from middleware
                let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                
                if middleware_tx_clone.send((json_str.clone(), promise_tx)).is_err() {
                    let _ = websocket_tx.send(json_str);
                    continue;
                }
                
                // Await result from middleware
                let ws_tx = websocket_tx.clone();
                let fallback = json_str;
                tokio::spawn(async move {
                    match promise_rx.recv().await {
                        Some(enriched) => {
                            let _ = ws_tx.send(enriched);
                        }
                        None => {
                            let _ = ws_tx.send(fallback);
                        }
                    }
                });
            }
        });

        // Spawn middleware handler (simulates JS callback invocation)
        let middleware_handler = tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                // Call middleware function (simulates JS execution)
                match middleware_fn(json_str) {
                    Ok(enriched) => {
                        let _ = promise_tx.send(enriched);
                    }
                    Err(_) => {
                        // Promise rejected, channel will be dropped
                    }
                }
            }
        });

        // Send test hops
        let test_hops = [
            serde_json::json!({
                "type": "hop",
                "clientId": "test-client",
                "ttl": 1,
                "ip": "192.168.1.1",
                "router": "192.168.1.1",
                "rtt_ms": 1.5,
            }),
            serde_json::json!({
                "type": "hop",
                "clientId": "test-client",
                "ttl": 2,
                "ip": "10.0.0.1",
                "router": "10.0.0.1",
                "rtt_ms": 3.2,
            }),
            serde_json::json!({
                "type": "hop",
                "clientId": "test-client",
                "ttl": 3,
                "ip": "8.8.8.8",
                "router": "8.8.8.8",
                "rtt_ms": 15.7,
            }),
        ];

        for hop in test_hops.iter() {
            hop_queue_tx.send(hop.clone()).unwrap();
        }

        // Close sender to stop processing
        drop(hop_queue_tx);

        // Collect all websocket messages
        let mut results = Vec::new();
        while let Some(msg) = websocket_rx.recv().await {
            results.push(msg);
            if results.len() == 3 {
                break;
            }
        }

        // Wait for tasks to complete
        drop(middleware_tx);
        middleware_handler.await.unwrap();
        middleware_processor.await.unwrap();

        // Verify results
        assert_eq!(results.len(), 3);
        
        for (idx, result) in results.iter().enumerate() {
            let enriched: serde_json::Value = serde_json::from_str(result).unwrap();
            
            // Verify original data
            assert_eq!(enriched["type"], "hop");
            assert_eq!(enriched["clientId"], "test-client");
            assert_eq!(enriched["ttl"], idx as u8 + 1);
            
            // Verify enrichment
            assert!(enriched.get("geo").is_some());
            let geo = enriched["geo"].as_object().unwrap();
            assert_eq!(geo["city"], "Test City");
            assert_eq!(geo["country"], "Test Country");
            assert_eq!(geo["latitude"], 51.5074);
            assert_eq!(geo["longitude"], -0.1278);
        }

        // Verify middleware was called for each hop
        assert_eq!(received_hops.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_middleware_timeout_fallback() {
        // Test that original data is sent if middleware times out
        
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel::<serde_json::Value>();
        let (websocket_tx, mut websocket_rx) = mpsc::unbounded_channel::<String>();
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();

        // Middleware processor
        tokio::spawn(async move {
            while let Some(hop_message) = hop_queue_rx.recv().await {
                let json_str = serde_json::to_string(&hop_message).unwrap();
                let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                
                if middleware_tx.send((json_str.clone(), promise_tx)).is_err() {
                    let _ = websocket_tx.send(json_str);
                    continue;
                }
                
                let ws_tx = websocket_tx.clone();
                let fallback = json_str;
                tokio::spawn(async move {
                    // Simulate timeout
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    
                    match promise_rx.recv().await {
                        Some(enriched) => {
                            let _ = ws_tx.send(enriched);
                        }
                        None => {
                            // Fallback to original
                            let _ = ws_tx.send(fallback);
                        }
                    }
                });
            }
        });

        // Middleware that never responds (simulates timeout)
        tokio::spawn(async move {
            while let Some((_json_str, _promise_tx)) = middleware_rx.recv().await {
                // Drop promise_tx without sending - simulates timeout/error
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        // Send test hop
        let test_hop = serde_json::json!({
            "type": "hop",
            "ttl": 1,
            "ip": "192.168.1.1",
        });
        hop_queue_tx.send(test_hop.clone()).unwrap();
        drop(hop_queue_tx);

        // Wait for result
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let result = websocket_rx.recv().await.unwrap();
        let received: serde_json::Value = serde_json::from_str(&result).unwrap();
        
        // Should be original data (fallback)
        assert_eq!(received["type"], "hop");
        assert_eq!(received["ttl"], 1);
        assert!(received.get("geo").is_none()); // No enrichment
    }

    #[tokio::test]
    async fn test_multiple_concurrent_clients() {
        // Test that middleware handles multiple concurrent connections
        
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();

        let received_hops = Arc::new(Mutex::new(Vec::new()));
        let middleware_fn = create_test_middleware(received_hops.clone());

        // Middleware handler
        let handler = tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                if let Ok(enriched) = middleware_fn(json_str) {
                    let _ = promise_tx.send(enriched);
                }
            }
        });

        // Simulate 5 concurrent clients, each sending 10 hops
        let mut client_tasks = Vec::new();
        
        for client_id in 0..5 {
            let middleware_tx_clone = middleware_tx.clone();
            
            let task = tokio::spawn(async move {
                let mut results = Vec::new();
                
                for ttl in 1..=10 {
                    let hop = serde_json::json!({
                        "type": "hop",
                        "clientId": format!("client-{}", client_id),
                        "ttl": ttl,
                        "ip": format!("10.0.{}.{}", client_id, ttl),
                        "rtt_ms": (client_id * 10 + ttl) as f64,
                    });
                    
                    let json_str = serde_json::to_string(&hop).unwrap();
                    let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                    
                    middleware_tx_clone.send((json_str.clone(), promise_tx)).unwrap();
                    
                    if let Some(enriched) = promise_rx.recv().await {
                        results.push(enriched);
                    }
                }
                
                results
            });
            
            client_tasks.push(task);
        }

        // Wait for all clients
        let mut all_results = Vec::new();
        for task in client_tasks {
            let results = task.await.unwrap();
            all_results.extend(results);
        }

        drop(middleware_tx);
        handler.await.unwrap();

        // Verify all hops were processed
        assert_eq!(all_results.len(), 50); // 5 clients × 10 hops
        assert_eq!(received_hops.lock().unwrap().len(), 50);

        // Verify enrichment
        for result_str in all_results {
            let result: serde_json::Value = serde_json::from_str(&result_str).unwrap();
            assert!(result.get("geo").is_some());
        }
    }

    #[tokio::test]
    async fn test_middleware_error_handling() {
        // Test middleware that returns errors
        
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();

        // Error-producing middleware
        let error_middleware = |json_str: String| -> Result<String> {
            let hop: serde_json::Value = serde_json::from_str(&json_str)
                .map_err(|e| Error::from_reason(format!("Parse error: {}", e)))?;
            
            // Fail on TTL 2
            if hop["ttl"] == 2 {
                return Err(Error::from_reason("Simulated middleware error"));
            }
            
            Ok(json_str)
        };

        tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                match error_middleware(json_str) {
                    Ok(result) => {
                        let _ = promise_tx.send(result);
                    }
                    Err(_) => {
                        // Drop promise_tx - simulates rejected promise
                    }
                }
            }
        });

        // Send 3 hops
        let mut results = Vec::new();
        for ttl in 1..=3 {
            let hop = serde_json::json!({
                "type": "hop",
                "ttl": ttl,
                "ip": "192.168.1.1",
            });
            
            let json_str = serde_json::to_string(&hop).unwrap();
            let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
            
            middleware_tx.send((json_str.clone(), promise_tx)).unwrap();
            
            // Wait with timeout
            let result = tokio::time::timeout(
                tokio::time::Duration::from_millis(50),
                promise_rx.recv()
            ).await;
            
            results.push((ttl, result));
        }

        // Verify results
        // TTL 1 succeeds - receives data
        assert!(results[0].1.is_ok());
        assert!(results[0].1.as_ref().unwrap().is_some());
        
        // TTL 2 times out (error) - channel closed, receives None
        assert!(results[1].1.is_ok());
        assert!(results[1].1.as_ref().unwrap().is_none());
        
        // TTL 3 succeeds - receives data
        assert!(results[2].1.is_ok());
        assert!(results[2].1.as_ref().unwrap().is_some());
    }

    #[test]
    fn test_hop_data_structure() {
        // Test various hop data structures
        
        let test_cases = vec![
            // Minimal hop
            serde_json::json!({
                "type": "hop",
                "ttl": 1,
                "ip": "192.168.1.1",
            }),
            // Full hop with MPLS
            serde_json::json!({
                "type": "hop",
                "clientId": "client-1",
                "ttl": 5,
                "ip": "10.0.0.1",
                "router": "10.0.0.1",
                "rtt_ms": 12.34,
                "mpls": [
                    {"label": 100, "exp": 0, "ttl": 255},
                    {"label": 200, "exp": 5, "ttl": 254}
                ],
            }),
            // Hop with modifications
            serde_json::json!({
                "type": "hop",
                "ttl": 3,
                "ip": "8.8.8.8",
                "modifications": {
                    "ttl_modified": true,
                    "flags_modified": false,
                    "modifications": ["TTL decreased by 2"]
                },
            }),
            // Timeout hop
            serde_json::json!({
                "type": "hop",
                "ttl": 10,
                "timeout": true,
            }),
        ];

        for hop in test_cases {
            // Test serialization/deserialization
            let json_str = serde_json::to_string(&hop).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
            assert_eq!(hop, parsed);
            
            // Test that type field is present
            assert_eq!(hop["type"], "hop");
        }
    }
}
