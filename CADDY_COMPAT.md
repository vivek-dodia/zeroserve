# Caddy Compatibility

This document records the current state of zeroserve's Caddy compatibility
layer. It is a practical compatibility target, not a claim that zeroserve is a
drop-in replacement for the full Caddy runtime.

## Scope

zeroserve can adapt supported Caddyfiles to Caddy JSON and can compile supported
Caddy HTTP JSON to a generated zeroserve eBPF/C middleware script. The generated
middleware runs in zeroserve's request-processing surface, so features outside
that surface are either ignored with warnings where they have no request effect,
or rejected when approximating them would be misleading.

Supported work is centered on HTTP request routing, matchers, header mutation,
URI rewriting, basic static responses, static file serving, selected reverse
proxy behavior, response hooks, variables, maps, and basic authentication.

## Entry Points

- `--caddy-compile <path>` compiles a Caddy JSON config, or a Caddyfile
  path which is first adapted to JSON, and writes generated C middleware to
  stdout.
- `--caddy <path>` runs a Caddyfile (or Caddy JSON) directly end to end:
  adapt -> compile -> in-memory site tarball -> serve. The generated
  middleware C and the resulting tarball live entirely in memory (memfd); no
  SITE_TAR argument is needed.
- Caddy-translated middleware uses the bundled `zeroserve_caddy.h` helper layer
  instead of emitting large helper implementations inline.
- Response processing hooks are registered through the `zs_call` mechanism and
  run during response processing for the current request.
- The metadata map is shared between request and response phases. Existing
  response-header-in-metadata-map behavior continues to work.

## Caddyfile Adapter

The adapter implements the supported directive set needed by the compiler and
tracks Caddy behavior for many parser and validation edge cases. Current covered
areas include:

- site address parsing, wildcard hosts, duplicate/ambiguous site validation, and
  known-directive-as-address diagnostics
- global options needed for directive ordering and filesystem definitions, with
  warnings or errors for unsupported runtime options
- imports, import globs, snippet registration from imported files, snippet
  arguments, `{block}`, `{blocks.name}`, named routes, and heredocs
- canonical route ordering for supported directives, including `handle`,
  `handle_path`, `route`, `handle_errors`, and named route invocation
- matcher syntax for path, method, host, header, query, vars, regexp, file,
  `not`, and supported expression forms
- directives including `respond`, `redir`, `map`, `vars`, `root`, `rewrite`,
  `uri`, `try_files`, `file_server`, `request_header`, `header`,
  `request_body`, `basic_auth`, `reverse_proxy`, `forward_auth`, `intercept`,
  `log`, `log_skip`, `bind`, `tls`, `metrics`, `acme_server`, and
  observability directives where relevant to validation

Unsupported Caddyfile directives or subdirectives should fail during adaptation
or compile with explicit diagnostics instead of silently generating incorrect
middleware.

## JSON Compiler

The JSON compiler supports these Caddy HTTP handlers in the generated
middleware:

- `static_response`
- `error`
- `headers`
- `rewrite`
- `request_body` for request size/time limits only
- `reverse_proxy` for supported single-request proxy behavior
- `intercept` for supported response-header/status hooks
- `file_server`
- `vars`
- `map`
- `invoke`
- `subroute`
- `authentication` with HTTP basic auth
- `push` where representable as generated response headers
- `log_append` and `tracing` as validated no-op/ignored observability surfaces

The compiler validates unknown fields on supported handlers, routes, matchers,
servers, and apps where zeroserve has a modeled schema. This is intentional:
unrecognized Caddy JSON often means behavior zeroserve cannot reproduce.

## Runtime Behavior Implemented

Current generated middleware support includes:

- route matching and ordering for supported Caddy route structures
- request method, host, path, query, header, remote IP, client IP, regexp, file,
  vars, expression, and `not` matchers
- placeholder expansion for supported request, original request, regexp,
  variable, map, file matcher, reverse-proxy response-header, and error-status
  placeholders
- static responses, redirects, and Caddy-compatible redirect HTML bodies
- request header set/add/delete/replace
- response header set/add/delete/replace, including deferred response hooks and
  response matcher conditions
- URI/path/query rewrite operations, including set/add/delete/rename/replace
  query operations and regexp path replacement
- maps with defaults, literal mappings, regexp mappings, typed Caddyfile
  outputs, and multiple destinations
- basic auth with bcrypt and argon2id hashes, challenge responses, credential
  checks, and `{http.auth.user.id}`
- file serving from packed tarball content and from configured filesystem roots
  only when zeroserve is started with `--expose-filesystem`
- Caddyfile/Caddy JSON access logging to `output file ...` targets, written by
  a dedicated monoio/io_uring logging thread when `--expose-filesystem` is
  enabled; without that flag, file logging is a no-op
- file-server options including root, hide, index names, status code,
  pass-thru, browse sort/file limit, sidecar ETags, and selected precompressed
  sidecar behavior
- error routes and `handle_errors` for supported error status handling
- reverse proxying to supported static or placeholder-expanded upstreams,
  selected request rewrite/header mutation, response-header hooks, response
  status replacement, and `forward_auth` copied-header behavior
- response hook registration and execution through `zs_call`

## Intentional Exclusions

zeroserve does not attempt to support Caddy compatibility features that require
body rewriting/copying or Caddy's full server runtime. In particular:

- no `Via` header injection or handling
- no Caddy request body rewriting
- no Caddy response body rewriting, response body copying, or response body
  suppression
- no `templates`, `encode`, or `copy_response` generated behavior
- no `zs_req_set_body`, `zs_res_set_body`, `zs_res_suppress_body`, or
  `zs_res_copy_body` APIs
- no generic `zs_res_set_header`, `zs_res_append_header`, or
  `zs_res_delete_header` APIs
- no TLS automation, listener management, certificate management, ACME server
  runtime, ECH, or PKI runtime behavior
- no Prometheus metrics serving
- no PHP FastCGI runtime behavior
- no full Caddy logging/tracing runtime behavior beyond supported file access
  logs
- no advanced reverse-proxy load balancing, retry, health-check, dynamic
  upstream, or transport/TLS customization semantics
- no filesystem exposure unless `--expose-filesystem` is explicitly provided

Unsupported surfaces should be rejected or warned about clearly. They should not
be approximated in generated middleware.

## Validation State

Current validation combines Rust unit tests and Deno end-to-end tests. The most
important checks are:

- `cargo test --bin zeroserve caddyfile::adapter:: -- --nocapture`
- `cargo test --bin zeroserve caddy_compile::tests:: -- --nocapture`
- `cargo test --bin zeroserve server::caddy::tests:: -- --nocapture`
- `cargo test helpers::`
- `cargo build --release`
- `cd testing && deno test -A caddy_e2e_compare_test.ts`
- relevant focused tests in `testing/caddy_compile_test.ts`
- `cargo fmt --check`
- `git diff --check`

The live comparison tests start stock `caddy run` and zeroserve against generated
Caddyfiles, then compare actual HTTP responses for supported behavior. Several
cases are ported or adapted from `/mnt/jfs/caddy/caddytest/integration`.

## Known Incomplete Areas

The current implementation is intentionally narrower than Caddy. Remaining risk
is mostly in exact edge-case parity:

- broader Caddyfile parser/provisioning diagnostics
- long-tail global option/module validation
- uncommon route sorting and matcher combinations
- advanced file-server HTTP semantics such as range and conditional request
  combinations not yet covered by live comparisons
- placeholder timing and unsupported placeholder diagnostics outside covered
  paths
- deeper response-hook ordering interactions across proxy, file-server, and
  error-route boundaries
- reverse-proxy behavior beyond the supported single-request/header/status hook
  surface

These gaps are documented rather than hidden. Future compatibility work should
prefer Caddy's own fixtures from `/mnt/jfs/caddy/caddytest/integration` and
should keep unsupported body-rewrite/runtime features rejected.
