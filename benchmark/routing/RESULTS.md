# Routing/matching optimization results

Benchmark: `benchmark/routing/benchmark.py`. Synthetic Caddyfile with N http-only
vhosts, each with a `path` matcher route, a `path_regexp` route, a `handle`
subroute, and a root fallback. Server runs with `--threads 3`, load is
`wrk -t2 -c64 -d3s` (best of 2 runs after warmup), on the 8-core dev machine.

Scenarios:

- **first** — host that sorts first in the route chain (best case)
- **last** — host that sorts last (worst case: every route's matcher evaluated)
- **last-re** — regexp route on the last host
- **miss** — host matching no route (full walk, 200 fallback)

## Requests/sec by phase

| label     | N   | first   | last    | last-re | miss    |
|-----------|-----|---------|---------|---------|---------|
| baseline  | 8   | 260,461 | 251,848 | 150,320 | 272,646 |
| phase1    | 8   | 257,101 | 268,398 | 217,910 | 300,061 |
| phase2    | 8   | 276,000 | 269,345 | 187,106¹| 306,421 |
| phase3    | 8   | 279,433 | 280,319 | 162,362¹| 315,931 |
| phase4    | 8   | 292,951 | 293,718 | 240,033 | 321,041 |
| phase2-24 | 24  | 219,100¹| 253,049 | 204,236 | 277,733 |
| phase3-24 | 24  | 284,335 | 266,776 | 214,716 | 296,067 |
| phase4-24 | 24  | 272,218 | 276,431 | 222,400 | 301,135 |
| phase3-32 | 32  | 283,239 | 255,667 | 220,583 | 291,066 |
| phase4-32 | 32  | 292,473 | 274,156 | 225,089 | 304,180 |

¹ noisy run (p99 outlier in the raw data); treat as run-to-run variance.

Baseline → phase4 at N=8: **+12% first, +17% last, +60% last-re, +18% miss**,
with p99 latency roughly halved (e.g. miss 1.99ms → 0.54ms).

## Stock Caddy (built from /Users/user/Projects/caddy @ d3986f8, GOMAXPROCS=3)

| label     | N   | first   | last    | last-re | miss    |
|-----------|-----|---------|---------|---------|---------|
| caddy-8   | 8   | 253,416 | 234,165 | 215,976 | 286,351 |
| caddy-32  | 32  | 254,963 | 202,427 | 182,951 | 224,600 |
| caddy-256 | 256 | 271,947 | 82,274  | 80,185  | 88,584  |

At N=32, zeroserve (phase4) leads stock Caddy by ~15% on first, ~35% on
last/miss, ~23% on last-re, with ~4× lower p99 (≈0.5ms vs ≈2.4ms). Stock
Caddy's linear route walk shows clear positional degradation as N grows
(82k req/s for the last of 256 hosts vs 272k for the first); zeroserve's
host dispatch table keeps last ≈ first, but zeroserve currently cannot load
N=256 (see limits below).

## Scale limits (this site shape)

| stage    | compiles (llc, cpu v3) | loads at runtime |
|----------|------------------------|------------------|
| baseline | ≤ 13 sites (BPF stack) | ≤ 13             |
| phase2   | ≤ 128 (branch range)   | ~24–31 (JIT zone)|
| phase3/4 | ≥ 256 (512 fails)      | ~32–63 (JIT zone)|

- Baseline failed >13 sites because every host matcher declared its own
  256-byte buffer at `entry()` function scope, blowing the 4 KiB BPF stack.
  Phase 2's per-route brace scoping lets LLVM overlay those slots.
- The runtime ceiling is async-ebpf's fixed 64 KiB JIT code zone
  (`code_len_allocated` in async-ebpf 0.3.1 program.rs); raising it (or
  shrinking per-site handler code) is the lever for 256+ vhost configs.
- N=512 also exceeds BPF's 16-bit branch range under `-mcpu=v3`; `-mcpu=v4`
  (long jumps) compiles it, if the VM gains v4 support.

### With the local async-ebpf checkout (1 MiB default code zone)

Switching Cargo.toml to `async-ebpf = { path = "../async-ebpf" }` lifts the
load ceiling: N=64/128/256 all load. At N=256 (phase4-256-localebpf):
first 298k / last 193k / last-re 166k / miss 211k req/s — 2.1-2.4× stock
Caddy on last/regexp/miss with p99 ≤ 0.7ms vs 4.4-4.9ms. The remaining
positional fall-off (298k → 193k) is the per-non-matching-route
`else if (zs_response_pending() != 0)` host call; the generator could skip
that clause for routes whose matchers cannot leave a response pending.

## Three-way comparison: zeroserve vs stock Caddy vs nginx (2026-06-11)

Same harness, all three servers re-run back-to-back in one session
(`cmp-{server}-{N}` labels in results.jsonl). zeroserve at HEAD (eaf9828,
async-ebpf 0.3.2 with the now-default 1 MiB JIT code zone — N=256 loads
without the local async-ebpf checkout). Caddy is the same stock build as
above (GOMAXPROCS=3). nginx 1.24.0 (Ubuntu) with `worker_processes 3` and an
equivalent config: one `server` block per vhost (`^~` prefix locations for
/api/ and /static/ to mirror Caddy's route order, the `~ ^/items/...` regex
location, a `location /` fallback, and a `default_server` returning the same
empty 200 for the miss case); `keepalive_requests 1000000` so nginx does not
recycle wrk's connections every 1000 requests. Config generator:
`gen_nginx_conf` in benchmark.py, `--server nginx` to run it.

Requests/sec (p99 in parentheses):

| N   | server    | first          | last           | last-re        | miss           |
|-----|-----------|----------------|----------------|----------------|----------------|
| 8   | zeroserve | 261k (0.80ms)  | 277k (0.91ms)  | 196k (1.22ms)  | 311k (0.43ms)  |
| 8   | caddy     | 182k (3.85ms)  | 198k (3.35ms)  | 200k (2.86ms)  | 228k (3.01ms)  |
| 8   | nginx     | 531k (2.04ms)  | 602k (1.71ms)  | 522k (2.09ms)  | 576k (2.01ms)  |
| 32  | zeroserve | 263k (0.73ms)  | 278k (0.44ms)  | 225k (0.49ms)  | 268k (0.67ms)  |
| 32  | caddy     | 212k (2.84ms)  | 165k (3.96ms)  | 171k (3.20ms)  | 186k (3.37ms)  |
| 32  | nginx     | 681k (1.81ms)  | 627k (2.59ms)  | 547k (2.27ms)  | 532k (1.75ms)  |
| 256 | zeroserve | 297k (0.41ms)  | 171k (1.03ms)  | 165k (0.55ms)  | 185k (0.81ms)  |
| 256 | caddy     | 186k (4.57ms)  | 70k (5.34ms)   | 76k (5.29ms)   | 84k (5.00ms)   |
| 256 | nginx     | 521k (1.69ms)  | 457k (1.85ms)  | 582k (2.04ms)  | 594k (2.00ms)  |

Takeaways:

- **zeroserve vs Caddy**: ahead at every N and scenario except a wash on
  last-re at N=8; the gap widens with N (N=256 last/miss: ~2.2-2.5×, and
  p99 is 5-10× lower throughout).
- **nginx vs both**: nginx is ~2× zeroserve and 3-7× Caddy on raw throughput
  here, essentially flat in N — its hash-based `server_name` lookup plus
  static `return` directives make this workload close to nginx's ideal case.
  Its p50 (~60µs) is ~3× better than zeroserve's, though zeroserve keeps the
  lowest p99 of the three (0.4-1.2ms vs nginx's 1.7-2.6ms).
- **Positional fall-off**: nginx last ≈ first at all N; zeroserve degrades
  297k → 171k at N=256 (the per-non-matching-route `zs_response_pending()`
  host call noted above); Caddy degrades hardest (186k → 70k, linear walk).
- nginx's miss case is its *fastest* path at N=256 (default_server, no
  location matching), whereas it is the slowest for zeroserve.

## zeroserve with --disable-request-logging (HTTP, 2026-06-11)

The three-way table above ran zeroserve with per-request logging on, while
nginx had `access_log off` and stock Caddy logs nothing by default. The
harness now always passes `--disable-request-logging`; re-run of the
zeroserve rows (`nolog-zeroserve-{N}`), same session as the table above:

| N   | first   | last    | last-re | miss    |
|-----|---------|---------|---------|---------|
| 8   | 333,110 | 359,541 | 255,319 | 354,373 |
| 32  | 351,324 | 288,819 | 304,486 | 334,064 |
| 256 | 318,630 | 175,761 | 203,272 | 217,582 |

Logging off is worth ~+15-30% across the board. Against nginx this narrows
the gap to ~1.6-2× (from ~2×); the N=256 positional fall-off
(319k -> 176k first->last) is unchanged, as expected for a constant
per-request cost.

## Three-way comparison over HTTPS (2026-06-11)

Same harness with `--tls`: a self-signed ECDSA P-256 cert for `*.bench`
shared by all three servers, TLS on port 18443, HTTP/1.1 over TLS (wrk does
not negotiate ALPN). The Caddyfile sites become `https://host:18443` with
per-site `tls cert key`; zeroserve runs with `--tls-addr` plus the same cert
as the `--cert/--key` no-SNI default and `--disable-request-logging`; nginx
gets `listen 18443 ssl` with the cert at http level. Clients connect by
hostname (bench names resolve to 127.0.0.1 via /etc/hosts) so SNI matches
the request Host. Labels `tls-{server}-{N}` in results.jsonl.

Requests/sec (p99 in parentheses):

| N   | server    | first          | last           | last-re        | miss           |
|-----|-----------|----------------|----------------|----------------|----------------|
| 8   | zeroserve | 243k (0.91ms)  | 220k (0.90ms)  | 213k (1.69ms)  | 229k (1.05ms)  |
| 8   | caddy     | 169k (2.83ms)  | 142k (3.71ms)  | 139k (3.98ms)  | 179k (3.42ms)  |
| 8   | nginx     | 336k (1.99ms)  | 304k (1.92ms)  | 343k (1.94ms)  | 361k (1.13ms)  |
| 32  | zeroserve | 228k (1.21ms)  | 229k (0.92ms)  | 189k (2.52ms)  | 251k (0.85ms)  |
| 32  | caddy     | 173k (3.10ms)  | 127k (4.33ms)  | 136k (3.64ms)  | 108k (5.40ms)  |
| 32  | nginx     | 307k (2.70ms)  | 287k (1.64ms)  | 301k (1.90ms)  | 326k (2.00ms)  |
| 256 | zeroserve | 187k (1.21ms)  | 152k (1.36ms)  | 126k (1.44ms)  | 189k (1.20ms)  |
| 256 | caddy     | 172k (3.12ms)  | 63k (7.54ms)   | 68k (6.17ms)   | 67k (5.70ms)   |
| 256 | nginx     | 341k (1.98ms)  | 323k (1.69ms)  | 298k (1.80ms)  | 313k (1.91ms)  |

Takeaways:

- Ranking unchanged from HTTP: nginx > zeroserve > Caddy everywhere.
  TLS costs zeroserve ~25-40% vs its HTTP-nolog numbers, nginx ~30-40%,
  Caddy ~10-25% (Caddy was already routing-bound, so crypto hides behind it
  less).
- zeroserve leads Caddy 1.3-2.8×, with the largest gaps at N=256
  (last/miss/regex 2.4-2.8×) and p99 3-6× lower. nginx leads zeroserve
  ~1.4-2.4×.
- The N=256 positional fall-off persists over TLS for zeroserve
  (187k -> 152k) and Caddy (172k -> 63k); nginx stays flat.

Methodology notes (the traps are worth recording):

- wrk copies the URL host — even an IP literal — into SNI. zeroserve
  answers 421 when SNI is present and does not match the request Host
  (`request_authority_sni_mismatch`, src/server.rs), so an earlier run that
  connected to `https://127.0.0.1` "benchmarked" the 421 fast path at
  330-430k req/s. run_wrk now fails hard if wrk reports any non-2xx/3xx
  responses, and TLS runs connect by hostname (SNI == Host). The same
  IP-literal SNI made stock Caddy refuse handshakes outright: its
  `fallback_sni` is looked up *exactly* in the cert cache, so it must be
  set to the literal SAN `*.bench`, not to a hostname the wildcard covers.
- Python's urllib sends no SNI for IP URLs, so sanity checks passed while
  wrk failed — readiness/sanity and load generation must use the same
  connection shape.

## HTTPS-to-HTTP reverse proxy (2026-06-11)

`--tls --proxy`: every vhost is just `reverse_proxy 127.0.0.1:18090`
(nginx: `proxy_pass` to an `upstream` with `keepalive`, `proxy_http_version
1.1`, `Connection ""`, `Host $host` — without the keepalive upstream nginx
would open a backend connection per request while Caddy and zeroserve pool
theirs; zeroserve pools via ProxyPool, src/pool.rs). The shared backend is a
separate 2-worker nginx answering a fixed 200 (proxy 3 threads + wrk 2 +
backend 2 = 7 of 8 cores). first/last/last-re all traverse TLS termination +
routing + proxy + upstream round trip; `miss` is *not* proxied (the local
empty-200 fallback) and serves as the no-proxy baseline. Labels
`ptls-{server}-{N}` in results.jsonl.

Requests/sec (p99 in parentheses):

| N  | server    | first          | last           | last-re        | miss (no proxy) |
|----|-----------|----------------|----------------|----------------|-----------------|
| 8  | zeroserve | 154k (1.47ms)  | 152k (2.09ms)  | 142k (1.66ms)  | 263k (0.81ms)   |
| 8  | caddy     | 87k (3.32ms)   | 74k (3.97ms)   | 84k (3.41ms)   | 262k (2.23ms)   |
| 8  | nginx     | 230k (1.24ms)  | 215k (1.50ms)  | 257k (1.10ms)  | 360k (2.06ms)   |
| 32 | zeroserve | 146k (1.39ms)  | 160k (1.01ms)  | 146k (1.34ms)  | 269k (0.75ms)   |
| 32 | caddy     | 79k (3.80ms)   | 81k (3.32ms)   | 69k (4.36ms)   | 223k (2.26ms)   |
| 32 | nginx     | 223k (1.31ms)  | 263k (1.45ms)  | 219k (1.58ms)  | 399k (2.11ms)   |

Takeaways:

- Proxying through to the backend, zeroserve sustains ~142-160k req/s —
  **~1.8-2.1× stock Caddy** (69-87k) with p99 2-3× lower. nginx leads
  zeroserve ~1.5-1.7× (215-263k).
- Cost of the proxy hop (vs the respond-only HTTPS table above, N=8 first):
  zeroserve 243k -> 154k (-37%), nginx 336k -> 230k (-32%), Caddy
  169k -> 87k (-49%). Caddy's reverse_proxy is its most expensive handler
  here; zeroserve's zs_reverse_proxy keeps the same relative position it has
  on respond-only traffic.
- The miss column tracks the respond-only numbers (zeroserve 263-269k vs
  229-251k in the HTTPS table), confirming the backend was not the
  bottleneck for the proxied scenarios.
- One zeroserve N=32 cell initially failed with wrk exiting 1 mid-suite;
  a manual repro of the same config ran clean (147k/139k), so it was
  transient. run_wrk now includes wrk's output in failures instead of
  swallowing it (and still hard-fails on any non-2xx).

## What each phase changed

1. **phase1** (src/helpers/caddy.rs): cache compiled regexes and parsed
   regexp-matcher configs (thread-local, keyed by pattern/config string);
   allocation-free fast paths in path matching (Cow + skip placeholder
   expansion when no `{`).
2. **phase2** (src/caddy_compile.rs): brace-scope each route; hoist the Host
   header read+normalize to a single `entry()` prologue shared by all host
   matchers, with re-reads after handlers that can mutate Host (`headers`
   request ops touching Host, `zeroserve_call`).
3. **phase3** (src/caddy_compile.rs, sdk/zeroserve_caddy.h): sorted exact-host
   dispatch table in `.rodata`; one binary-search lookup per request, each
   exact host matcher becomes an integer compare. Wildcard/placeholder
   patterns keep the label-wise matcher.
4. **phase4** (src/helpers/caddy.rs, src/caddy_compile.rs): one
   `zs_caddy_path_match_multi` host call per `path` matcher (NUL-separated
   patterns, compile-time lowercased) instead of one call per pattern, plus a
   per-request cache of the decoded/lowercased/cleaned path-match subject.
   (Originally scoped as a C port of path matching + regex pre-registration;
   the host-call batching + value-keyed caches deliver the same wins without
   porting Caddy's escaped-path semantics to C or adding a registration
   protocol — the regex cache hit is already O(1).)
