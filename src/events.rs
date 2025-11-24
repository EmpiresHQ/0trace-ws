use napi::threadsafe_function::{ThreadsafeFunction, ErrorStrategy};
use std::sync::{Arc, Mutex, OnceLock};
use std::collections::HashMap;

type EventCallback = ThreadsafeFunction<String, ErrorStrategy::Fatal>;

pub struct EventBusInner {
    listeners: Mutex<HashMap<String, Vec<EventCallback>>>,
}

impl Default for EventBusInner {
    fn default() -> Self {
        Self {
            listeners: Mutex::new(HashMap::new()),
        }
    }
}

impl Drop for EventBusInner {
    fn drop(&mut self) {
        // Release all threadsafe functions when event bus is dropped
        let mut listeners = self.listeners.lock().unwrap();
        for (_, callbacks) in listeners.drain() {
            for cb in callbacks {
                cb.abort().ok();
            }
        }
    }
}

pub struct EventBus(Arc<EventBusInner>);

impl EventBus {
    pub fn new() -> Self {
        Self(Arc::new(Default::default()))
    }

    pub fn register(&self, event: String, cb: napi::JsFunction) -> anyhow::Result<()> {
        // Convert JS function to ThreadsafeFunction
        let tsfn = cb.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<String>| {
                // Parse JSON string to object and pass to callback
                let global = ctx.env.get_global()?;
                let json_obj: napi::JsObject = global.get_named_property("JSON")?;
                let json_parse: napi::JsFunction = json_obj.get_named_property("parse")?;
                let json_str = ctx.env.create_string(&ctx.value)?;
                let event_obj: napi::JsUnknown = json_parse.call(None, &[json_str])?;
                
                Ok(vec![event_obj])
            },
        )?;
        
        // Store the callback
        let mut listeners = self.0.listeners.lock().unwrap();
        listeners.entry(event).or_default().push(tsfn);
        
        Ok(())
    }

    pub fn off(&self, event: &str) {
        // Remove all listeners for this event
        let mut listeners = self.0.listeners.lock().unwrap();
        if let Some(callbacks) = listeners.remove(event) {
            // Abort all threadsafe functions for this event
            for cb in callbacks {
                cb.abort().ok();
            }
        }
    }

    pub fn emit(&self, typ: &str, payload: &serde_json::Value) {
        let event_data = serde_json::json!({"type": typ, "payload": payload}).to_string();
        
        let listeners = self.0.listeners.lock().unwrap();
        if let Some(callbacks) = listeners.get(typ) {
            for cb in callbacks {
                cb.call(
                    event_data.clone(),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
            }
        }
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