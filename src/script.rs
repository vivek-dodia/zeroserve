use std::{
    any::Any,
    cell::RefCell,
    collections::HashMap,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow};
use async_ebpf::{
    helpers::{Helper, write_cstr},
    program::{
        GlobalEnv, HelperScope, Program, ProgramEventListener, ProgramLoader, TimesliceConfig,
        Timeslicer, UnboundProgram,
    },
};
use futures::{
    FutureExt, StreamExt,
    channel::{mpsc, oneshot},
};
use monoio::fs::File;
use ulid::Ulid;

use crate::{logging::async_log, site::Site};

const SCRIPT_ENTRYPOINT: &str = "zeroserve.request";

static SCRIPT_HELPERS: &[(&str, Helper)] = &[
    ("zs_log", h_log),
    ("zs_date", h_now_ms),
    ("zs_now_ms", h_now_ms),
    ("zs_req_method", h_req_method),
    ("zs_req_path", h_req_path),
    ("zs_req_uri", h_req_uri),
    ("zs_req_query", h_req_query),
    ("zs_req_scheme", h_req_scheme),
    ("zs_req_peer", h_req_peer),
    ("zs_req_header", h_req_header),
    ("zs_req_query_param", h_req_query_param),
    ("zs_meta_get", h_meta_get),
    ("zs_meta_set", h_meta_set),
    ("zs_respond", h_respond),
];

static HELPER_TABLES: &[&[(&str, Helper)]] = &[SCRIPT_HELPERS];

#[derive(Clone, Debug)]
pub struct ScriptRequest {
    pub request_id: Ulid,
    pub method: String,
    pub path: String,
    pub uri: String,
    pub query: String,
    pub scheme: String,
    pub peer: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

impl ScriptRequest {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.get(&name).map(String::as_str)
    }

    fn query_param(&self, name: &str) -> Option<&str> {
        self.query_params.get(name).map(String::as_str)
    }
}

#[derive(Clone, Debug)]
pub struct ScriptResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Default)]
pub struct ScriptOutcome {
    pub metadata: HashMap<String, String>,
    pub response: Option<ScriptResponse>,
}

struct ScriptExecutionContext {
    request: Arc<ScriptRequest>,
    metadata: HashMap<String, String>,
    response: Option<ScriptResponse>,
    script_name: String,
    log_buffer: RefCell<Vec<u8>>,
}

pub struct ScriptRuntime {
    tx: mpsc::UnboundedSender<Cmd>,
}

enum Cmd {
    Reload {
        scripts: HashMap<String, UnboundProgram>,
        tx: oneshot::Sender<()>,
    },
    RunRequest {
        request: ScriptRequest,
        tx: oneshot::Sender<ScriptOutcome>,
    },
}

#[derive(Clone, Debug)]
pub struct ScriptRuntimeConfig {
    pub preempt_timer_interval: Duration,
}

impl ScriptRuntime {
    pub unsafe fn new(config: ScriptRuntimeConfig) -> Self {
        let g = unsafe { GlobalEnv::new() };
        let (tx, rx) = mpsc::unbounded();
        monoio::spawn(script_worker(g, rx, config));
        ScriptRuntime { tx }
    }

    pub async fn reload(&self, site: Arc<Site>) -> anyhow::Result<()> {
        let pl = ProgramLoader::new(
            &mut rand::thread_rng(),
            Arc::new(EventListener),
            HELPER_TABLES,
        );
        let file = site
            .tar_file
            .try_clone()
            .and_then(File::from_std)
            .with_context(|| "failed to prepare tar file")?;
        let scripts: RefCell<HashMap<String, UnboundProgram>> = RefCell::new(HashMap::new());
        futures::future::join_all(site.entries.iter().map(|(path, entry)| {
            let scripts = &scripts;
            let file = &file;
            let pl = &pl;
            async move {
                let Some(name) = path.strip_prefix(".zeroserve/scripts/") else {
                    return;
                };
                if !name.ends_with(".o") {
                    return;
                }
                let (Ok(()), buf) = file
                    .read_exact_at(vec![0u8; entry.size as usize], entry.offset)
                    .await
                else {
                    return;
                };
                let prog = match pl.load(&mut rand::thread_rng(), &buf) {
                    Ok(x) => x,
                    Err(err) => {
                        async_log(
                            format!("failed to load script '{}': {:?}\n", name, err).into_bytes(),
                        )
                        .await;
                        return;
                    }
                };
                async_log(format!("compiled script '{}'\n", name).into_bytes()).await;
                scripts.borrow_mut().insert(name.to_string(), prog);
            }
        }))
        .await;
        let (tx, rx) = oneshot::channel();
        let scripts = scripts.into_inner();
        let _ = self.tx.unbounded_send(Cmd::Reload { scripts, tx });
        rx.await.with_context(|| "worker failed")
    }

    pub async fn run_request(&self, request: ScriptRequest) -> anyhow::Result<ScriptOutcome> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .unbounded_send(Cmd::RunRequest { request, tx })
            .map_err(|_| anyhow!("script worker is unavailable"))?;
        rx.await.with_context(|| "worker failed")
    }
}

async fn script_worker(
    g: GlobalEnv,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    config: ScriptRuntimeConfig,
) {
    let t = g.init_thread(config.preempt_timer_interval);
    let mut scripts: Rc<Vec<(String, Program)>> = Rc::new(Vec::new());
    let timeslice = TimesliceConfig {
        max_run_time_before_throttle: Duration::from_millis(20),
        max_run_time_before_yield: Duration::from_millis(1),
        throttle_duration: Duration::from_millis(100),
    };

    loop {
        let Some(cmd) = rx.next().await else {
            break;
        };
        match cmd {
            Cmd::Reload {
                scripts: new_scripts,
                tx,
            } => {
                let mut next: Vec<(String, Program)> = new_scripts
                    .into_iter()
                    .map(|(k, v)| (k, v.pin_to_current_thread(t)))
                    .collect();
                next.sort_by(|a, b| a.0.cmp(&b.0));
                scripts = Rc::new(next);
                let _ = tx.send(());
            }
            Cmd::RunRequest { request, mut tx } => {
                let scripts = scripts.clone();
                let timeslice = timeslice.clone();
                monoio::spawn(async move {
                    let request_id = request.request_id;
                    let outcome = monoio::select! {
                      _ = tx.cancellation() => {
                        async_log(
                            format!(
                                "[script_runtime] {}: canceled\n",
                                request_id,
                            )
                            .into_bytes(),
                        )
                        .await;
                        return;
                      },
                      x = run_request_scripts(&scripts, request, &timeslice, &MonoioTimeslicer) => x,
                    };
                    let _ = tx.send(outcome);
                });
            }
        }
    }
}

async fn run_request_scripts(
    scripts: &[(String, Program)],
    request: ScriptRequest,
    timeslice: &TimesliceConfig,
    timeslicer: &impl Timeslicer,
) -> ScriptOutcome {
    if scripts.is_empty() {
        return ScriptOutcome::default();
    }

    let request = Arc::new(request);
    let mut metadata: HashMap<String, String> = HashMap::new();
    let mut response: Option<ScriptResponse> = None;

    for (name, program) in scripts {
        if !program.has_section(SCRIPT_ENTRYPOINT) {
            continue;
        }

        let mut ctx = ScriptExecutionContext {
            request: request.clone(),
            metadata,
            response: None,
            script_name: name.clone(),
            log_buffer: RefCell::new(vec![]),
        };
        let mut resources: [&mut dyn Any; 1] = [&mut ctx];
        let run = program
            .run(
                timeslice,
                timeslicer,
                SCRIPT_ENTRYPOINT,
                &mut resources,
                &[],
            )
            .await;
        if let Err(err) = run {
            eprintln!("script '{}' failed: {:?}", name, err);
        }

        metadata = ctx.metadata;
        if let Some(script_response) = ctx.response {
            response = Some(script_response);
            break;
        }
    }

    ScriptOutcome { metadata, response }
}

fn with_ectx<R>(
    scope: &async_ebpf::program::HelperScope,
    f: impl FnOnce(&mut ScriptExecutionContext) -> Result<R, ()>,
) -> Result<R, ()> {
    scope.with_resource_mut(|res: Result<&mut ScriptExecutionContext, ()>| match res {
        Ok(ctx) => f(ctx),
        Err(_) => Err(()),
    })
}

fn read_utf8<'a>(
    scope: &'a async_ebpf::program::HelperScope,
    ptr: u64,
    len: u64,
) -> Result<&'a str, ()> {
    let data = scope.user_memory(ptr, len)?;
    std::str::from_utf8(&data).map_err(|_| ())
}

fn write_str(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    value: &str,
) -> Result<u64, ()> {
    if out_len == 0 {
        return Ok(value.len() as u64);
    }
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    Ok(write_cstr(&[value.as_bytes()], &mut out))
}

fn h_log(
    scope: &async_ebpf::program::HelperScope,
    msg_ptr: u64,
    msg_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let mut msg = scope.user_memory(msg_ptr, msg_len)?;
    let newline_index = msg.iter().enumerate().find(|x| *x.1 == b'\n').map(|x| x.0);
    with_ectx(scope, |ctx| {
        let mut buf = ctx.log_buffer.borrow_mut();
        if newline_index.is_none() && buf.len() < 512 {
            buf.extend_from_slice(msg);
            return Ok(());
        }
        if let Some(i) = newline_index {
            buf.extend_from_slice(&msg[..i]);
            msg = &msg[i + 1..];
        }
        for b in &mut *buf {
            if !b.is_ascii() || (b.is_ascii_control() && *b != b'\t') {
                *b = b'?';
            }
        }
        let output = format!(
            "[user_log] {}: {}: {}\n",
            ctx.request.request_id,
            ctx.script_name,
            std::str::from_utf8(&buf).unwrap_or("(invalid)")
        );
        buf.clear();
        buf.extend_from_slice(msg);
        scope.post_task(async move {
            async_log(output.into_bytes()).await;
            |_: &HelperScope| Ok(0)
        });
        Ok(())
    })?;
    Ok(0)
}

fn h_now_ms(
    _: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(now.as_millis() as u64)
}

fn h_req_method(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.method)
    })
}

fn h_req_path(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.path)
    })
}

fn h_req_uri(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.uri)
    })
}

fn h_req_query(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.query)
    })
}

fn h_req_scheme(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.scheme)
    })
}

fn h_req_peer(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        write_str(scope, out_ptr, out_len, &ctx.request.peer)
    })
}

fn h_req_header(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.header(name.trim()).unwrap_or("");
        write_str(scope, out_ptr, out_len, value)
    })
}

fn h_req_query_param(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.query_param(name.trim()).unwrap_or("");
        write_str(scope, out_ptr, out_len, value)
    })
}

fn h_meta_get(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx
            .metadata
            .get(key.trim())
            .map(String::as_str)
            .unwrap_or("");
        write_str(scope, out_ptr, out_len, value)
    })
}

fn h_meta_set(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err(());
    }
    let value = read_utf8(scope, val_ptr, val_len)?.to_string();
    with_ectx(scope, |ctx| {
        ctx.metadata.insert(key, value);
        Ok(0)
    })
}

fn h_respond(
    scope: &async_ebpf::program::HelperScope,
    status: u64,
    body_ptr: u64,
    body_len: u64,
    content_type_ptr: u64,
    content_type_len: u64,
) -> Result<u64, ()> {
    let status = u16::try_from(status).map_err(|_| ())?;
    let body = if body_len == 0 {
        Vec::new()
    } else {
        scope.user_memory(body_ptr, body_len)?.to_vec()
    };
    let content_type = if content_type_len == 0 {
        None
    } else {
        Some(read_utf8(scope, content_type_ptr, content_type_len)?.to_string())
    };
    with_ectx(scope, |ctx| {
        ctx.response = Some(ScriptResponse {
            status,
            body,
            content_type,
        });
        Ok(0)
    })
}

struct MonoioTimeslicer;

impl Timeslicer for MonoioTimeslicer {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        monoio::time::sleep(duration)
    }

    fn yield_now(&self) -> impl Future<Output = ()> {
        monoio::time::sleep(Duration::from_millis(0))
    }
}

struct EventListener;

impl ProgramEventListener for EventListener {
    fn did_throttle(&self, scope: &HelperScope) -> Option<Pin<Box<dyn Future<Output = ()>>>> {
        with_ectx(scope, |ctx| {
            let msg = format!(
                "[script_runtime] {}: {}: throttling\n",
                ctx.request.request_id, ctx.script_name
            );
            Ok(Some(async_log(msg.into_bytes()).boxed_local()))
        })
        .unwrap()
    }
}
