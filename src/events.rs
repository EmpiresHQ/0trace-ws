use napi::JsFunction;
use std::sync::{Arc, OnceLock};
use tokio::sync::broadcast;

pub struct EventBusInner {
    tx: broadcast::Sender<String>,
}

impl Default for EventBusInner {
    fn default() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self { tx }
    }
}

pub struct EventBus(Arc<EventBusInner>);

impl EventBus {
    pub fn new() -> Self {
        Self(Arc::new(Default::default()))
    }

    pub fn register(&self, event: String, cb: JsFunction) -> anyhow::Result<()> {
        // TODO: Implement proper event callback registration
        // For now, just subscribe to prevent compilation errors
        // In a proper implementation, we'd need to use napi::threadsafe_function
        let _rx = self.0.tx.subscribe();
        let _ = (event, cb); // Suppress unused warnings
        Ok(())
    }

    pub fn emit(&self, typ: &str, payload: &serde_json::Value) {
        let _ = self
            .0
            .tx
            .send(serde_json::json!({"type": typ, "payload": payload}).to_string());
    }
}

static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();

pub fn event_bus() -> &'static EventBus {
    EVENT_BUS.get_or_init(EventBus::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_creation() {
        let bus = EventBus::new();
        let payload = serde_json::json!({"test": "value"});
        
        // Should not panic
        bus.emit("test_event", &payload);
    }
}
