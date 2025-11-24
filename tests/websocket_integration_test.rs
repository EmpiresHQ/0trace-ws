//! Integration test for full WebSocket + ICMP + Middleware flow
//! This test simulates the complete traceroute pipeline

use napi::bindgen_prelude::*;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Duration;

#[derive(Debug, Clone)]
struct MockIcmpResponse {
    ttl: u8,
    router_ip: String,
    delay_ms: u64,
}

#[derive(Debug, Clone)]
struct MockWebSocketMessage {
    payload: String,
}

/// Mock ICMP poller that simulates network responses
async fn mock_icmp_poller(
    responses: Vec<MockIcmpResponse>,
    hop_tx: mpsc::UnboundedSender<serde_json::Value>,
) {
    for response in responses {
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(response.delay_ms)).await;
        
        let hop_data = serde_json::json!({
            "type": "hop",
            "clientId": "mock-client-123",
            "ttl": response.ttl,
            "ip": response.router_ip,
            "router": response.router_ip,
            "rtt_ms": response.delay_ms as f64,
            "mpls": [],
            "modifications": null,
        });
        
        if hop_tx.send(hop_data).is_err() {
            break;
        }
    }
}

/// Mock WebSocket writer
async fn mock_websocket_writer(
    mut message_rx: mpsc::UnboundedReceiver<String>,
    output_buffer: Arc<Mutex<Vec<MockWebSocketMessage>>>,
) {
    while let Some(message) = message_rx.recv().await {
        output_buffer.lock().unwrap().push(MockWebSocketMessage {
            payload: message,
        });
    }
}

/// Mock middleware that enriches hop data
fn create_geoip_middleware(
    call_count: Arc<Mutex<usize>>,
) -> impl Fn(String) -> Result<String> {
    move |json_str: String| {
        *call_count.lock().unwrap() += 1;
        
        let mut hop: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| Error::from_reason(format!("JSON error: {}", e)))?;
        
        // Simulate GeoIP lookup based on IP
        let ip = hop["ip"].as_str().unwrap_or("");
        let (city, country, lat, lon) = match ip {
            ip if ip.starts_with("192.168") => ("Local Network", "LAN", 0.0, 0.0),
            ip if ip.starts_with("10.") => ("Private Network", "RFC1918", 0.0, 0.0),
            "8.8.8.8" => ("Mountain View", "United States", 37.4056, -122.0775),
            "1.1.1.1" => ("San Francisco", "United States", 37.7749, -122.4194),
            _ => ("Unknown", "Unknown", 0.0, 0.0),
        };
        
        if let Some(obj) = hop.as_object_mut() {
            obj.insert(
                "geo".to_string(),
                serde_json::json!({
                    "city": city,
                    "country": country,
                    "latitude": lat,
                    "longitude": lon,
                }),
            );
        }
        
        Ok(serde_json::to_string(&hop).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_traceroute_pipeline() {
        // Setup: Create the full pipeline
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel::<serde_json::Value>();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel::<String>();
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();

        let call_count = Arc::new(Mutex::new(0));
        let middleware = create_geoip_middleware(call_count.clone());
        let websocket_buffer = Arc::new(Mutex::new(Vec::new()));

        // Mock ICMP responses (simulating traceroute to 8.8.8.8)
        let mock_responses = vec![
            MockIcmpResponse {
                ttl: 1,
                router_ip: "192.168.1.1".to_string(),
                delay_ms: 1,
            },
            MockIcmpResponse {
                ttl: 2,
                router_ip: "10.0.0.1".to_string(),
                delay_ms: 5,
            },
            MockIcmpResponse {
                ttl: 3,
                router_ip: "1.1.1.1".to_string(),
                delay_ms: 10,
            },
            MockIcmpResponse {
                ttl: 4,
                router_ip: "8.8.8.8".to_string(),
                delay_ms: 15,
            },
        ];

        // Spawn all pipeline components
        
        // 1. ICMP poller (source of hop data)
        let poller_task = tokio::spawn(mock_icmp_poller(
            mock_responses.clone(),
            hop_queue_tx.clone(),
        ));

        // 2. Middleware processor (reads from hop_queue, sends to middleware_tx)
        let middleware_processor = tokio::spawn(async move {
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

        // 3. Middleware handler (calls JS middleware function)
        let middleware_handler = tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                // Simulate async JS execution delay
                tokio::time::sleep(Duration::from_millis(2)).await;
                
                match middleware(json_str) {
                    Ok(enriched) => {
                        let _ = promise_tx.send(enriched);
                    }
                    Err(_) => {
                        // Promise rejected
                    }
                }
            }
        });

        // 4. WebSocket writer (collects final output)
        let ws_buffer = websocket_buffer.clone();
        let writer_task = tokio::spawn(mock_websocket_writer(websocket_rx, ws_buffer));

        // Wait for ICMP poller to finish
        poller_task.await.unwrap();
        drop(hop_queue_tx);

        // Wait for pipeline to complete
        middleware_processor.await.unwrap();
        middleware_handler.await.unwrap();
        writer_task.await.unwrap();

        // Verify results
        let messages = websocket_buffer.lock().unwrap();
        assert_eq!(messages.len(), 4, "Should receive 4 hop messages");
        assert_eq!(*call_count.lock().unwrap(), 4, "Middleware should be called 4 times");

        // Verify each hop
        for (idx, msg) in messages.iter().enumerate() {
            let hop: serde_json::Value = serde_json::from_str(&msg.payload).unwrap();
            
            let expected_ttl = (idx + 1) as u64;
            assert_eq!(hop["ttl"], expected_ttl);
            assert_eq!(hop["type"], "hop");
            assert_eq!(hop["clientId"], "mock-client-123");
            
            // Verify GeoIP enrichment
            assert!(hop.get("geo").is_some(), "Hop {} should have geo data", idx);
            let geo = hop["geo"].as_object().unwrap();
            assert!(geo.contains_key("city"));
            assert!(geo.contains_key("country"));
            assert!(geo.contains_key("latitude"));
            assert!(geo.contains_key("longitude"));
        }

        // Verify specific IPs were enriched correctly
        let hop1: serde_json::Value = serde_json::from_str(&messages[0].payload).unwrap();
        assert_eq!(hop1["geo"]["country"], "LAN");
        
        let hop2: serde_json::Value = serde_json::from_str(&messages[1].payload).unwrap();
        assert_eq!(hop2["geo"]["country"], "RFC1918");
        
        let hop3: serde_json::Value = serde_json::from_str(&messages[2].payload).unwrap();
        assert_eq!(hop3["geo"]["city"], "San Francisco");
        
        let hop4: serde_json::Value = serde_json::from_str(&messages[3].payload).unwrap();
        assert_eq!(hop4["geo"]["city"], "Mountain View");
        assert_eq!(hop4["ip"], "8.8.8.8");
    }

    #[tokio::test]
    async fn test_traceroute_with_timeouts() {
        // Test handling of timeout hops
        
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        let websocket_buffer = Arc::new(Mutex::new(Vec::new()));

        // Middleware processor
        tokio::spawn(async move {
            while let Some(hop_message) = hop_queue_rx.recv().await {
                let json_str = serde_json::to_string(&hop_message).unwrap();
                let _ = websocket_tx.send(json_str);
            }
        });

        // WebSocket writer
        let ws_buffer = websocket_buffer.clone();
        tokio::spawn(mock_websocket_writer(websocket_rx, ws_buffer));

        // Send mix of successful and timeout hops
        for ttl in 1..=10 {
            let hop_data = if ttl % 3 == 0 {
                // Timeout hop
                serde_json::json!({
                    "type": "hop",
                    "ttl": ttl,
                    "timeout": true,
                })
            } else {
                // Successful hop
                serde_json::json!({
                    "type": "hop",
                    "ttl": ttl,
                    "ip": format!("10.0.0.{}", ttl),
                    "rtt_ms": ttl as f64 * 2.5,
                })
            };
            
            hop_queue_tx.send(hop_data).unwrap();
        }
        
        drop(hop_queue_tx);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify
        let messages = websocket_buffer.lock().unwrap();
        assert_eq!(messages.len(), 10);

        let mut timeout_count = 0;
        let mut success_count = 0;

        for msg in messages.iter() {
            let hop: serde_json::Value = serde_json::from_str(&msg.payload).unwrap();
            
            if hop.get("timeout").and_then(|v| v.as_bool()).unwrap_or(false) {
                timeout_count += 1;
                assert!(hop.get("ip").is_none() || hop["ip"].is_null());
            } else {
                success_count += 1;
                assert!(hop.get("ip").is_some());
            }
        }

        assert_eq!(timeout_count, 3); // TTL 3, 6, 9
        assert_eq!(success_count, 7);
    }

    #[tokio::test]
    async fn test_middleware_processing_order() {
        // Verify that hops are processed in order
        
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();
        let websocket_buffer = Arc::new(Mutex::new(Vec::new()));

        let processing_order = Arc::new(Mutex::new(Vec::new()));
        let order_clone = processing_order.clone();

        // Middleware that records processing order
        tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                let hop: serde_json::Value = serde_json::from_str(&json_str).unwrap();
                let ttl = hop["ttl"].as_u64().unwrap();
                order_clone.lock().unwrap().push(ttl);
                
                let _ = promise_tx.send(json_str);
            }
        });

        // Processor
        tokio::spawn(async move {
            while let Some(hop_message) = hop_queue_rx.recv().await {
                let json_str = serde_json::to_string(&hop_message).unwrap();
                let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                
                middleware_tx.send((json_str.clone(), promise_tx)).unwrap();
                
                let ws_tx = websocket_tx.clone();
                tokio::spawn(async move {
                    if let Some(result) = promise_rx.recv().await {
                        let _ = ws_tx.send(result);
                    }
                });
            }
        });

        // Writer
        let ws_buffer = websocket_buffer.clone();
        tokio::spawn(mock_websocket_writer(websocket_rx, ws_buffer));

        // Send hops in order
        for ttl in 1..=20 {
            hop_queue_tx.send(serde_json::json!({
                "type": "hop",
                "ttl": ttl,
                "ip": format!("10.0.0.{}", ttl),
            })).unwrap();
        }
        
        drop(hop_queue_tx);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify order
        let order = processing_order.lock().unwrap();
        assert_eq!(order.len(), 20);
        
        for (idx, ttl) in order.iter().enumerate() {
            assert_eq!(*ttl, (idx + 1) as u64);
        }
    }

    #[tokio::test]
    async fn test_high_throughput_scenario() {
        // Test with many concurrent clients
        
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();
        let call_count = Arc::new(Mutex::new(0));
        let middleware = create_geoip_middleware(call_count.clone());

        // Middleware handler
        tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                if let Ok(result) = middleware(json_str) {
                    let _ = promise_tx.send(result);
                }
            }
        });

        // Simulate 100 clients, each with 30 hops
        let mut tasks = Vec::new();
        
        for client_id in 0..100 {
            let middleware_tx_clone = middleware_tx.clone();
            
            let task = tokio::spawn(async move {
                let mut success_count = 0;
                
                for ttl in 1..=30 {
                    let hop = serde_json::json!({
                        "type": "hop",
                        "clientId": format!("client-{}", client_id),
                        "ttl": ttl,
                        "ip": format!("10.{}.{}.{}", client_id / 256, client_id % 256, ttl),
                        "rtt_ms": (ttl * 2) as f64,
                    });
                    
                    let json_str = serde_json::to_string(&hop).unwrap();
                    let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                    
                    if middleware_tx_clone.send((json_str, promise_tx)).is_ok()
                        && promise_rx.recv().await.is_some()
                    {
                        success_count += 1;
                    }
                }
                
                success_count
            });
            
            tasks.push(task);
        }

        // Wait for all clients
        let mut total_success = 0;
        for task in tasks {
            total_success += task.await.unwrap();
        }

        assert_eq!(total_success, 3000); // 100 clients × 30 hops
        assert_eq!(*call_count.lock().unwrap(), 3000);
    }

    #[tokio::test]
    async fn test_middleware_with_mpls_data() {
        // Test handling of hops with MPLS labels
        
        let (hop_queue_tx, mut hop_queue_rx) = mpsc::unbounded_channel();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        let (middleware_tx, mut middleware_rx) = mpsc::unbounded_channel::<(
            String,
            mpsc::UnboundedSender<String>,
        )>();
        let websocket_buffer = Arc::new(Mutex::new(Vec::new()));
        let call_count = Arc::new(Mutex::new(0));
        let middleware = create_geoip_middleware(call_count.clone());

        // Middleware handler
        tokio::spawn(async move {
            while let Some((json_str, promise_tx)) = middleware_rx.recv().await {
                if let Ok(enriched) = middleware(json_str) {
                    let _ = promise_tx.send(enriched);
                }
            }
        });

        // Processor
        tokio::spawn(async move {
            while let Some(hop_message) = hop_queue_rx.recv().await {
                let json_str = serde_json::to_string(&hop_message).unwrap();
                let (promise_tx, mut promise_rx) = mpsc::unbounded_channel();
                
                middleware_tx.send((json_str.clone(), promise_tx)).unwrap();
                
                let ws_tx = websocket_tx.clone();
                tokio::spawn(async move {
                    if let Some(result) = promise_rx.recv().await {
                        let _ = ws_tx.send(result);
                    }
                });
            }
        });

        // Writer
        let ws_buffer = websocket_buffer.clone();
        tokio::spawn(mock_websocket_writer(websocket_rx, ws_buffer));

        // Send hop with MPLS data
        let hop_with_mpls = serde_json::json!({
            "type": "hop",
            "clientId": "test-client",
            "ttl": 5,
            "ip": "10.0.0.5",
            "router": "10.0.0.5",
            "rtt_ms": 8.5,
            "mpls": [
                {"label": 100200, "exp": 0, "ttl": 255},
                {"label": 300400, "exp": 5, "ttl": 254},
            ],
            "modifications": {
                "ttl_modified": false,
                "flags_modified": false,
                "options_stripped": false,
                "tcp_flags_modified": false,
                "modifications": [],
            },
        });

        hop_queue_tx.send(hop_with_mpls).unwrap();
        drop(hop_queue_tx);
        
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify
        let messages = websocket_buffer.lock().unwrap();
        assert_eq!(messages.len(), 1);

        let result: serde_json::Value = serde_json::from_str(&messages[0].payload).unwrap();
        
        // Verify MPLS data preserved
        assert!(result.get("mpls").is_some());
        let mpls = result["mpls"].as_array().unwrap();
        assert_eq!(mpls.len(), 2);
        assert_eq!(mpls[0]["label"], 100200);
        assert_eq!(mpls[1]["label"], 300400);
        
        // Verify modifications preserved
        assert!(result.get("modifications").is_some());
        
        // Verify GeoIP added
        assert!(result.get("geo").is_some());
        assert_eq!(result["geo"]["country"], "RFC1918");
    }
}
