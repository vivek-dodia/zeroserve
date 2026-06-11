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
