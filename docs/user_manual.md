# Zeroserve User Manual

## Overview

Zeroserve serves a static website from a tarball and optionally runs eBPF request scripts.
It supports HTTP, HTTPS, hot reload, a small templating pass for text responses, and
an opt-in reverse proxy from scripts.

## Quick start

Serve a prebuilt tarball:

```bash
zeroserve --addr 0.0.0.0:8080 site.tar
```

Package a directory into a tarball and serve it:

```bash
# Create a tarball from the current directory
zeroserve --pack . > site.tar

# Serve it
zeroserve --addr 0.0.0.0:8080 site.tar
```

## Packaging a site

Zeroserve expects a tarball whose root corresponds to the site root.
Use `--pack` to build one from a directory:

```bash
zeroserve --pack ./public > site.tar
```

Packaging notes:
- All regular files under the directory are added to the tarball.
- Request scripts live under `.zeroserve/scripts/`.
- Any `.c` file in `.zeroserve/scripts/` is compiled to an `.o` eBPF object.
  The resulting `.o` is included in the tarball and the `.c` is omitted.
- If a `.c` and `.o` share the same name, the `.o` is skipped in favor of recompiling.
- Script compilation requires `clang` and `llc` on your `PATH`.

If you want the SDK header without packing:

```bash
zeroserve --dump-sdk > zeroserve.h
```

## Running the server

Command synopsis:

```bash
zeroserve [OPTIONS] SITE_TAR
```

Key options:
- `--addr <IP:PORT>`: HTTP bind address (default `0.0.0.0:8080`).
- `--tls-addr <IP:PORT>`: HTTPS bind address (requires `--cert` and `--key`).
- `--cert <FILE>`: TLS certificate PEM.
- `--key <FILE>`: TLS private key PEM.
- `--index <NAME>`: Default document for directories (default `index.html`).
- `--try-html`: Try `<path>.html` when a request path is missing.
- `--chunk-size <BYTES>`: Streaming chunk size for tar reads (default 65536).
- `--reload-signal-file <FILE>`: Poll a file and reload when its contents change.
- `--disable-request-logging`: Turn off per-request logs.
- `--enable-proxy-protocol`: Expect PROXY protocol v1 on each new connection.
- `--disable-ns-isolation`: Disable Linux namespace isolation.
- `--enable-netns-isolation`: Enable Linux network namespace isolation.
- `--preempt-timer-interval-ms <MS>`: Script preemption timer interval.
- `--sqpoll-idle-ms <MS>`: Enable io_uring sqpoll with idle timeout.

Examples:

```bash
# HTTP only
zeroserve --addr 0.0.0.0:8080 site.tar

# HTTP + HTTPS
zeroserve --addr 0.0.0.0:8080 \
  --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem \
  site.tar

# HTML fallback and PROXY protocol
zeroserve --try-html --enable-proxy-protocol site.tar
```

## Routing and file lookup

Zeroserve normalizes request paths (handles `.`/`..` and percent decoding) before lookup.
Lookup order:
- Direct match for the requested path.
- If the path is a directory (or looks like one), try `<path>/<index>`.
- Also tries `<path>/<index>` even without a trailing slash.
- If `--try-html` is enabled, try `<path>.html` when the path has no extension.

The default index document is `index.html`, configurable via `--index`.

## Hot reload

Zeroserve reloads the site tarball, scripts, and TLS configuration on:
- `SIGHUP` (for example: `killall -SIGHUP zeroserve`).
- Changes to `--reload-signal-file` (polled periodically, content-based).

This is useful for replacing the tarball and certificate in place without downtime.

## TLS

To enable HTTPS, provide a TLS address plus certificate and key:

```bash
zeroserve --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar
```

Reloading TLS assets uses the same hot-reload mechanism as the tarball.

## Request scripting (eBPF)

Zeroserve can run eBPF programs on every request. Scripts are loaded from
`.zeroserve/scripts/*.o` inside the tarball and executed in sorted path order.

Flow and behavior:
- Each script must export a function in section `zeroserve.request`.
  Use the `ZS_ENTRY` macro to mark the entrypoint.
- Scripts run for every request.
- A per-request metadata map is shared across scripts.
- If a script calls `zs_respond`, its response is sent and later scripts are skipped.
- If a script calls `zs_reverse_proxy`, the request is proxied and later scripts are skipped.
- Script failures are logged but do not abort the chain.

### Entry point

```c
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  // ...
  return 0;
}
```

### Building scripts

Option A: let `--pack` compile `.c` sources automatically.

```bash
zeroserve --pack ./site > site.tar
```

Option B: compile manually.

```bash
clang -O2 -target bpf -emit-llvm -c input.c -o tmp.bc
llc -march=bpf -bpf-stack-size=4096 -mcpu=v3 -filetype=obj tmp.bc -o out.o
```

Put the `.o` files at `.zeroserve/scripts/` in the tarball.

### Helper API overview

Logging and time:
- `zs_log(msg, len)`
- `zs_date()` and `zs_now_ms()` return milliseconds since the Unix epoch.

Request inspection:
- `zs_req_method`, `zs_req_path`, `zs_req_uri`, `zs_req_query`, `zs_req_scheme`, `zs_req_peer`
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)`

Request mutation:
- `zs_req_set_uri(uri, uri_len)`
- `zs_req_set_header(name, name_len, value, value_len)`
  (pass `value_len = 0` to remove the header)

Metadata:
- `zs_meta_get(key, key_len, out, out_len)`
- `zs_meta_set(key, key_len, value, value_len)`

Response/proxy:
- `zs_respond(status, body, body_len, content_type, content_type_len)`
- `zs_reverse_proxy(backend_url, backend_url_len)`

Helper notes:
- String helpers write C strings into the provided buffer.
- If `out_len = 0`, helpers return the required length.
- Header names are matched case-insensitively.

Examples:
- `examples/log_request.c` logs method and path.
- `examples/reverse_proxy.c` proxies `/api` to a backend.
- `examples/template.c` sets metadata for templating.
- `examples/health_response.c` returns a JSON health check.

**For a complete list of APIs, run `zeroserve --dump-sdk` to dump the SDK header.**

## Template substitution

When scripts set metadata, Zeroserve performs a simple template replacement on
static text responses. Any `<zs-meta>key</zs-meta>` placeholder (with optional
whitespace around the key) is replaced with the corresponding metadata value.

Rules:
- Only applies to text-like MIME types (HTML, CSS, JS, JSON, XML, SVG, etc.).
- Only runs for static file responses, not `zs_respond` bodies.
- Unknown keys are left as-is.

Example:

```html
<h1>Hello <zs-meta>name</zs-meta></h1>
```

If a script does `zs_meta_set("name", ..., "Ada", ...)`, the response becomes:

```html
<h1>Hello Ada</h1>
```

## Reverse proxy behavior

`zs_reverse_proxy` takes a backend URL such as `http://127.0.0.1:9000` or
`https://api.example.com/v1?token=abc`.

Zeroserve will:
- Append the request path to the backend base path.
- Merge the backend query string with the request query string.
- Use the backend host (and port if non-default) for the `Host` header.

Only `http` and `https` backends are supported.

## Operational notes

- Request logging is enabled by default; disable with `--disable-request-logging`.
- `--enable-proxy-protocol` is required when running behind a TCP load balancer
  that speaks PROXY protocol v1.
- `--disable-ns-isolation` and `--enable-netns-isolation` are Linux-specific
  isolation controls; leave them default unless you know you need them.
- Long-running scripts are throttled; keep scripts fast and avoid busy loops.

## Troubleshooting

- TLS startup errors: `--tls-addr` requires both `--cert` and `--key`.
- `--pack expects a directory`: pass a directory path, not a file.
- `tarball ... does not contain any regular files`: ensure your site has files.
- Script compilation fails: verify `clang` and `llc` are on `PATH`.
