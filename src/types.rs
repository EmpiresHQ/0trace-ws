use serde::Serialize;
use napi_derive::napi;
use tokio::sync::broadcast;

/// Information about packet modifications detected in ICMP response
#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct PacketModifications {
    /// TTL was modified (decreased more than expected)
    pub ttl_modified: bool,
    /// IP flags were modified
    pub flags_modified: bool,
    /// IP options were stripped
    pub options_stripped: bool,
    /// TCP flags were modified
    pub tcp_flags_modified: bool,
    /// Description of modifications
    pub modifications: Vec<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub client_id: String,
    pub ttl: u8,
    pub router: String,
    pub rtt_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifications: Option<PacketModifications>,
}

/// Request to enrich hop data via middleware
pub struct MiddlewareRequest {
    pub hop_json: String,
    pub response_tx: tokio::sync::oneshot::Sender<String>,
}

pub struct ServerTask {
    pub host: String,
    pub port: u16,
    pub max_hops: u32,
    pub per_ttl: u32,
    pub shutdown_tx: broadcast::Sender<()>,
    pub middleware_tx: Option<tokio::sync::mpsc::UnboundedSender<MiddlewareRequest>>,
}

#[napi(object)]
pub struct ServerOptions {
    pub host: Option<String>,
    pub port: u16,
    pub max_hops: Option<u32>,
    pub per_ttl_timeout_ms: Option<u32>,
    pub iface_hint: Option<String>,
    pub middleware: Option<napi::JsFunction>,
}

#[napi]
pub struct Server {
    pub(crate) task: std::sync::Arc<std::sync::Mutex<Option<ServerTask>>>,
    pub(crate) shutdown_tx: broadcast::Sender<()>,
}

#[napi]
impl Server {
    /// Start the server and block until it's stopped
    /// This method never returns unless the server is stopped via stop()
    #[napi]
    pub fn start(&self) -> napi::Result<()> {
        let task_option = self.task.lock().unwrap().take();
        let task = match task_option {
            Some(t) => t,
            None => return Err(napi::Error::from_reason("Server already started")),
        };

        // Create a dedicated Tokio runtime for the server
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| napi::Error::from_reason(format!("tokio runtime: {}", e)))?;

        // Block on the server loop - this will run until shutdown signal is received
        rt.block_on(crate::run_server_loop(
            task.host,
            task.port,
            task.max_hops,
            task.per_ttl,
            task.shutdown_tx,
            task.middleware_tx,
        ));

        Ok(())
    }

    /// Stop the server
    #[napi]
    pub fn stop(&self) -> napi::Result<()> {
        let _ = self.shutdown_tx.send(());
        Ok(())
    }

    /// Register event listener
    #[napi]
    pub fn on(&self, event: String, cb: napi::JsFunction) -> napi::Result<()> {
        crate::events::event_bus().register(event, cb)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    /// Remove all event listeners for a specific event
    #[napi]
    pub fn off(&self, event: String) -> napi::Result<()> {
        crate::events::event_bus().off(&event);
        Ok(())
    }
}
