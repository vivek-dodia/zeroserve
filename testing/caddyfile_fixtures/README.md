# Caddyfile adapter golden fixtures

These `*.caddy` files exercise zeroserve's Caddyfile -> Caddy JSON adapter
(`src/caddyfile/`). They are checked against upstream Caddy's own `caddy adapt`
to confirm the adapter reproduces Caddy's `apps.http` route trees.

To run the comparison you need a `caddy` binary (built from a Caddy checkout,
e.g. `go build -o /tmp/caddybin ./cmd/caddy`) and a release zeroserve build:

```bash
cargo build --release
python3 tools/caddyfile_golden.py /tmp/caddybin ./target/release/zeroserve \
    testing/caddyfile_fixtures
```

The harness compares only the substantive `apps.http.servers.*.routes` trees
(TLS/PKI/admin/logging apps and per-server listen/automatic-HTTPS fields are out
of zeroserve's eBPF surface and intentionally not reproduced). It also strips
`*.caddy` entries from `file_server` `hide` lists, since Caddy auto-hides its own
config path while zeroserve serves from a packed tarball.

Fixtures should stay within Caddyfile forms for which zeroserve is expected to
emit Caddy JSON. Explicitly excluded body-rewriting/copying surfaces such as
`templates` and `copy_response` are covered by focused rejection tests instead
of this parity harness.

End-to-end coverage (Caddyfile -> eBPF C) lives in `../caddyfile_test.ts`.
