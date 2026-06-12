use std::{
    cell::RefCell,
    collections::HashMap,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{
    channel::oneshot,
    future::{self, Either},
};
use monoio::net::{TcpStream, UnixStream};

use crate::boringtls::BoringStream;
use crate::http::h1::H1Connection;
use crate::hupwatch::HupWatcher;

const MAX_POOL_PER_KEY: usize = 128;
const MAX_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    host: String,
    port: u16,
    tls: bool,
}

impl PoolKey {
    pub fn new(host: String, port: u16, tls: bool) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
            tls,
        }
    }

    pub fn unix(path: String) -> Self {
        Self {
            host: format!("unix:{path}"),
            port: 0,
            tls: false,
        }
    }
}

pub enum PooledConnection {
    Http(H1Connection<TcpStream>),
    Https(H1Connection<BoringStream<TcpStream>>),
    Unix(H1Connection<UnixStream>),
}

impl PooledConnection {
    fn raw_fd(&self) -> Option<RawFd> {
        match self {
            PooledConnection::Http(conn) => conn.io_ref().map(AsRawFd::as_raw_fd),
            PooledConnection::Https(conn) => conn.io_ref().map(AsRawFd::as_raw_fd),
            PooledConnection::Unix(conn) => conn.io_ref().map(AsRawFd::as_raw_fd),
        }
    }
}

struct PoolEntry {
    conn: PooledConnection,
    last_used: Instant,
    token: u64,
    /// Dropping this cancels the hangup watch task for the entry.
    _hup_cancel: Option<oneshot::Sender<()>>,
}

pub struct ProxyPool {
    entries: HashMap<PoolKey, Vec<PoolEntry>>,
    next_token: u64,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_token: 0,
        }
    }

    pub fn take(&mut self, key: &PoolKey) -> Option<PooledConnection> {
        let Some(entries) = self.entries.get_mut(key) else {
            return None;
        };

        let now = Instant::now();
        while let Some(entry) = entries.pop() {
            if now.duration_since(entry.last_used) <= MAX_IDLE {
                if entries.is_empty() {
                    self.entries.remove(key);
                }
                return Some(entry.conn);
            }
        }

        self.entries.remove(key);
        None
    }

    pub fn put(&mut self, key: PoolKey, conn: PooledConnection) {
        let entries = self.entries.entry(key.clone()).or_default();
        if entries.len() >= MAX_POOL_PER_KEY {
            return;
        }
        let token = self.next_token;
        self.next_token += 1;
        entries.push(PoolEntry {
            _hup_cancel: watch_for_hangup(&key, token, &conn),
            conn,
            last_used: Instant::now(),
            token,
        });
    }

    fn evict(&mut self, key: &PoolKey, token: u64) {
        let Some(entries) = self.entries.get_mut(key) else {
            return;
        };
        let Some(idx) = entries.iter().position(|entry| entry.token == token) else {
            return;
        };
        entries.swap_remove(idx);
        if entries.is_empty() {
            self.entries.remove(key);
        }
    }
}

/// Watch the connection's fd for a backend hangup while it sits in the pool,
/// and evict the entry as soon as one is seen so it is never reused. Returns
/// the cancellation handle; dropping it (entry taken or pruned) stops the
/// watch task without evicting.
fn watch_for_hangup(
    key: &PoolKey,
    token: u64,
    conn: &PooledConnection,
) -> Option<oneshot::Sender<()>> {
    let hup = HUP_WATCHER.with(|watcher| watcher.borrow().clone())?;
    let hup_fut = hup.wait(conn.raw_fd()?).ok()?;
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let key = key.clone();
    monoio::spawn(async move {
        if let Either::Right(..) = future::select(cancel_rx, hup_fut).await {
            PROXY_POOL.with(|pool| pool.borrow_mut().evict(&key, token));
        }
    });
    Some(cancel_tx)
}

// Keep the pool thread-local since monoio sockets are !Send.
thread_local! {
    static PROXY_POOL: RefCell<ProxyPool> = RefCell::new(ProxyPool::new());
    static HUP_WATCHER: RefCell<Option<Arc<HupWatcher>>> = const { RefCell::new(None) };
}

/// Install this worker's hangup watcher so pooled backend connections are
/// monitored for peer close. Call once per worker thread during startup.
pub fn install_hup_watcher(hup: Arc<HupWatcher>) {
    HUP_WATCHER.with(|watcher| *watcher.borrow_mut() = Some(hup));
}

pub fn take_connection(key: &PoolKey) -> Option<PooledConnection> {
    PROXY_POOL.with(|pool| pool.borrow_mut().take(key))
}

pub fn return_connection(key: PoolKey, conn: PooledConnection) {
    PROXY_POOL.with(|pool| pool.borrow_mut().put(key, conn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::net::TcpListener;

    // Explicit runtime instead of `#[monoio::test]` for the same reason as the
    // boringtls loopback test: the macro cfg-gates on a feature we don't define.
    fn run(fut: impl Future<Output = ()>) {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(fut);
    }

    async fn pooled_pair(listener: &TcpListener) -> (PoolKey, monoio::net::TcpStream) {
        let addr = listener.local_addr().unwrap();
        let client = monoio::net::TcpStream::connect(addr).await.unwrap();
        let (backend_side, _) = listener.accept().await.unwrap();
        let key = PoolKey::new("127.0.0.1".to_string(), addr.port(), false);
        return_connection(
            key.clone(),
            PooledConnection::Http(H1Connection::new(client)),
        );
        (key, backend_side)
    }

    async fn wait_for_eviction(key: &PoolKey) -> bool {
        for _ in 0..200 {
            monoio::time::sleep(Duration::from_millis(5)).await;
            let evicted = PROXY_POOL.with(|pool| !pool.borrow().entries.contains_key(key));
            if evicted {
                return true;
            }
        }
        false
    }

    #[test]
    fn backend_hangup_evicts_pooled_connection() {
        run(async {
            install_hup_watcher(HupWatcher::new());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();

            let (key, backend_side) = pooled_pair(&listener).await;
            drop(backend_side);

            assert!(
                wait_for_eviction(&key).await,
                "dead connection was not evicted from the pool"
            );
            assert!(take_connection(&key).is_none());
        });
    }

    #[test]
    fn hangup_watch_rearms_after_take_and_repool() {
        run(async {
            install_hup_watcher(HupWatcher::new());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();

            let (key, backend_side) = pooled_pair(&listener).await;

            // Cycle the connection through take/put: the first one-shot epoll
            // registration is abandoned without firing, so the second put must
            // re-arm it (EPOLL_CTL_MOD path) rather than fail with EEXIST.
            let conn = take_connection(&key).expect("live connection should be reusable");
            monoio::time::sleep(Duration::from_millis(20)).await;
            return_connection(key.clone(), conn);

            drop(backend_side);
            assert!(
                wait_for_eviction(&key).await,
                "dead connection was not evicted after re-pooling"
            );
        });
    }
}
