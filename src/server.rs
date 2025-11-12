use std::{
    cell::RefCell,
    io::ErrorKind,
    os::fd::AsFd,
    rc::Rc,
    sync::{Arc, Weak},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use monoio::{
    fs::File,
    io::{
        AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Split, Splitable, sink::SinkExt,
        stream::Stream,
    },
    net::TcpListener,
};
use monoio_http::{
    common::{
        body::Body,
        error::HttpError,
        request::{Request, RequestHead},
        response::Response,
    },
    h1::{
        codec::{decoder::RequestDecoder, encoder::GenericEncoder},
        payload::{FixedPayload, Payload},
    },
};
use monoio_rustls::TlsError;

use crate::{
    shared::SharedState,
    site::{Site, TarEntry, guess_mime, normalize_request_path},
};

type HttpBody = Payload<Bytes, HttpError>;

pub async fn amain(shared: Arc<SharedState>) -> Result<()> {
    if shared.config.tls_addr.is_some() {
        let tls_state = shared.clone();
        monoio::spawn(async move {
            if let Err(err) = run_tls_listener(tls_state).await {
                eprintln!("TLS listener stopped: {err:?}");
            }
        });
    }

    run_http_listener(shared).await
}

async fn run_http_listener(shared: Arc<SharedState>) -> Result<()> {
    let listener = TcpListener::bind(shared.config.http_addr)
        .with_context(|| format!("failed to bind {}", shared.config.http_addr))?;
    eprintln!("listening on http://{}", shared.config.http_addr);
    loop {
        let (stream, addr) = listener.accept().await?;
        if stream.set_nodelay(true).is_err() {
            continue;
        }
        let state = shared.clone();
        monoio::spawn(async move {
            if let Err(err) = handle_connection(stream, addr, state, Scheme::Http).await {
                eprintln!("connection {} over http closed with error: {err:?}", addr);
            }
        });
    }
}

async fn run_tls_listener(shared: Arc<SharedState>) -> Result<()> {
    let addr = shared
        .config
        .tls_addr
        .ok_or_else(|| anyhow!("TLS listener requested without address"))?;
    let listener = TcpListener::bind(addr)
        .with_context(|| format!("failed to bind TLS listener on {addr}"))?;
    eprintln!("listening on https://{}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = shared.clone();
        monoio::spawn(async move {
            let tls_state = match state.tls.load_full() {
                Some(runtime) => runtime,
                None => {
                    eprintln!("dropping TLS connection {peer} due to missing TLS config");
                    return;
                }
            };
            match tls_state.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) =
                        handle_connection(tls_stream, peer, state, Scheme::Https).await
                    {
                        eprintln!("TLS conn {peer} closed with error: {err:?}");
                    }
                }
                Err(err) => log_tls_error(peer, err),
            }
        });
    }
}

fn log_tls_error(peer: std::net::SocketAddr, error: TlsError) {
    if let TlsError::Io(x) = &error {
        if x.kind() == ErrorKind::ConnectionReset || x.kind() == ErrorKind::UnexpectedEof {
            return;
        }
    }
    eprintln!("TLS handshake with {peer} failed: {error:?}");
}

async fn handle_connection<IO>(
    io: IO,
    peer: std::net::SocketAddr,
    shared: Arc<SharedState>,
    scheme: Scheme,
) -> Result<()>
where
    IO: AsyncReadRent + AsyncWriteRent + Split + 'static,
{
    let (r, mut w) = io.into_split();
    let mut decoder = RequestDecoder::new(r);
    while let Some(result) = decoder.next().await {
        match result {
            Ok(request) => {
                let method = request.method().clone();
                let uri = request.uri().clone();
                if !shared.config.disable_request_logging {
                    log_request(peer, scheme, &method, &uri).await;
                }
                handle_request(request, &shared, peer, &mut w).await;
            }
            Err(err) => {
                if let HttpError::IOError(x) = &err {
                    if x.kind() == ErrorKind::ConnectionReset
                        || x.kind() == ErrorKind::UnexpectedEof
                    {
                        break;
                    }
                }

                eprintln!(
                    "{} request from {peer} could not be parsed: {err}",
                    scheme.as_str()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn handle_request(
    req: Request,
    shared: &Arc<SharedState>,
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
) {
    let (head, body) = req.into_parts();
    drain_payload(body).await;

    match head.method {
        Method::GET | Method::HEAD => {
            if serve_static(&head, shared, head.method == Method::HEAD, peer, w)
                .await
                .is_none()
            {
                send_fixed(w, not_found()).await
            }
        }
        _ => send_fixed(w, method_not_allowed()).await,
    }
}

async fn send_fixed(w: &mut impl AsyncWriteRent, res: Response<Bytes>) {
    let _ = GenericEncoder::new(w)
        .send_and_flush(res.map(|x| Payload::Fixed(FixedPayload::<_, HttpError>::new(x))))
        .await;
}

async fn drain_payload(mut payload: HttpBody) {
    loop {
        match payload.next_data().await {
            Some(Ok(_)) => continue,
            Some(Err(_)) => continue,
            None => break,
        }
    }
}

async fn serve_static(
    head: &RequestHead,
    shared: &Arc<SharedState>,
    head_only: bool,
    peer: std::net::SocketAddr,
    w: &mut impl AsyncWriteRent,
) -> Option<()> {
    let path = normalize_request_path(head.uri.path())?;
    let site = shared.site.load_full();
    let entry = site.lookup(&path, &shared.config.index_file, shared.config.try_html)?;

    let header = format!(
        "HTTP/1.1 200 OK\r
content-length: {}\r
server: {}\r
accept-ranges: bytes\r
content-type: {}\r\n\r\n",
        entry.size,
        crate::SERVER_HEADER,
        guess_mime(&entry.path),
    );

    let _ = w.write_all(header.into_bytes()).await;

    if head_only {
        let _ = w.flush().await;
        return Some(());
    }

    match stream_tar_entry(entry.clone(), &site, shared.config.chunk_size, w).await {
        Ok(()) => {
            let _ = w.flush().await;
        }
        Err(e) => {
            if e.kind() != ErrorKind::ConnectionReset && e.kind() != ErrorKind::BrokenPipe {
                eprintln!("aborting stream with {} due to io error: {:?}", peer, e);
                let _ = w.shutdown().await;
            }
        }
    };
    Some(())
}

async fn stream_tar_entry(
    entry: Arc<TarEntry>,
    site: &Arc<Site>,
    chunk_size: usize,
    w: &mut impl AsyncWriteRent,
) -> std::io::Result<()> {
    thread_local! {
        static TAR_FILE_CACHE: RefCell<Vec<(Weak<Site>, Rc<File>)>> = RefCell::new(Vec::new());
    }

    let file = TAR_FILE_CACHE.with(|x| {
        let mut x = x.borrow_mut();
        x.retain(|x| x.0.strong_count() != 0);
        let site_weak = Arc::downgrade(site);
        if let Some(x) = x.iter().find(|x| x.0.ptr_eq(&site_weak)) {
            return Ok(x.1.clone());
        }
        let file = match site.tar_file.try_clone() {
            Ok(x) => Rc::new(File::from_std(x).unwrap()),
            Err(e) => {
                eprintln!("failed to create tar handle: {}", e);
                return Err(e);
            }
        };
        x.push((Arc::downgrade(&site), file.clone()));
        Ok(file)
    })?;

    let mut remaining = entry.size;
    let mut offset = entry.offset;
    let mut buffer = vec![0u8; chunk_size];
    while remaining > 0 {
        let read_len = remaining.min(chunk_size as u64) as usize;
        let view = monoio::buf::SliceMut::new(buffer, 0, read_len);
        let (res, view) = file.read_at(view, offset).await;
        buffer = view.into_inner();
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let view = monoio::buf::Slice::new(buffer, 0, n);
        let (res, view) = w.write_all(view).await;
        buffer = view.into_inner();
        res?;
        remaining -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

fn not_found() -> Response<Bytes> {
    text_response(StatusCode::NOT_FOUND, "Not Found")
}

fn method_not_allowed() -> Response<Bytes> {
    text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

fn text_response(status: StatusCode, body: &str) -> Response<Bytes> {
    http::Response::builder()
        .status(status)
        .header(http::header::SERVER, crate::SERVER_HEADER)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::copy_from_slice(body.as_bytes()))
        .unwrap()
}

async fn log_request(peer: std::net::SocketAddr, scheme: Scheme, method: &Method, uri: &Uri) {
    thread_local! {
        static STDERR: Rc<File> = Rc::new(File::from_std(
            std::fs::File::from(
                std::io::stderr().as_fd().try_clone_to_owned()
                    .expect("failed to clone stderr")
            )).unwrap());
    }
    let msg = format!("{} {} {} {}\n", scheme.as_str(), peer, method, uri).into_bytes();
    let stderr = STDERR.with(|x| x.clone());
    let _ = stderr.write_all_at(msg, 0).await;
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}
