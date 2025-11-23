use serde::Serialize;
use napi_derive::napi;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub client_id: String,
    pub ttl: u8,
    pub router: String,
    pub rtt_ms: f64,
}

#[derive(Clone)]
pub struct ServerCtl {
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

#[napi(object)]
pub struct ServerOptions {
    pub host: Option<String>,
    pub port: u16,
    pub max_hops: Option<u32>,
    pub per_ttl_timeout_ms: Option<u32>,
    pub iface_hint: Option<String>,
}

#[napi]
pub struct ServerHandle {
    #[allow(dead_code)] // Needed to keep runtime alive
    pub(crate) rt: tokio::runtime::Runtime,
    pub(crate) ctl: ServerCtl,
}

#[napi]
impl ServerHandle {
    #[napi]
    pub fn stop(&self) -> napi::Result<()> {
        let _ = self.ctl.shutdown_tx.send(());
        Ok(())
    }

    #[napi]
    pub fn on(&self, event: String, cb: napi::JsFunction) -> napi::Result<()> {
        super::events::event_bus().register(event, cb)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}
