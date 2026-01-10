use std::sync::{Arc, Mutex};

use arc_swap::{ArcSwap, ArcSwapOption};
use std::net::TcpListener;

use crate::{config::StaticConfig, script::ScriptRuntime, site::Site, tls::TlsRuntime};

pub struct SharedState {
    pub config: Arc<StaticConfig>,
    pub site: ArcSwap<Site>,
    pub tls: ArcSwapOption<TlsRuntime>,
    pub http_listener: Mutex<Option<TcpListener>>,
    pub tls_listener: Mutex<Option<TcpListener>>,
    pub script_runtime: ScriptRuntime,
}

impl SharedState {
    pub fn new(
        config: Arc<StaticConfig>,
        site: Arc<Site>,
        tls: Option<TlsRuntime>,
        http_listener: TcpListener,
        tls_listener: Option<TcpListener>,
        script_runtime: ScriptRuntime,
    ) -> Self {
        Self {
            config,
            site: ArcSwap::new(site),
            tls: ArcSwapOption::from(tls.map(Arc::new)),
            http_listener: Mutex::new(Some(http_listener)),
            tls_listener: Mutex::new(tls_listener),
            script_runtime,
        }
    }
}
