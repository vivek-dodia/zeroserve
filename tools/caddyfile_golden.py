#!/usr/bin/env python3
"""Compare zeroserve's Caddyfile adapter against upstream `caddy adapt`.

For each *.caddy fixture, runs both adapters and compares the substantive
apps.http route trees (ignoring TLS/PKI/admin/logging apps and per-server
listen/tls/automatic_https fields, which fall outside zeroserve's eBPF surface).

Usage:
  tools/caddyfile_golden.py <caddy-binary> <zeroserve-binary> <fixtures-dir>
"""
import json
import subprocess
import sys
from pathlib import Path


def strip_config_hide(node):
    """Caddy's file_server auto-hides the active Caddyfile path; zeroserve serves
    from a tarball and intentionally does not. Drop *.caddy entries from any
    `hide` list so the comparison ignores this environment-specific default."""
    if isinstance(node, dict):
        if isinstance(node.get("hide"), list):
            node["hide"] = [h for h in node["hide"] if not str(h).endswith(".caddy")]
            if not node["hide"]:
                del node["hide"]
        for v in node.values():
            strip_config_hide(v)
    elif isinstance(node, list):
        for v in node:
            strip_config_hide(v)
    return node


def http_servers(doc):
    strip_config_hide(doc)
    return ((doc or {}).get("apps", {}).get("http", {}) or {}).get("servers", {}) or {}


def routes_of(doc):
    """Flatten routes across servers (sorted by server name) for comparison."""
    servers = http_servers(doc)
    out = []
    for name in sorted(servers):
        srv = servers[name]
        out.append({"server": name, "routes": srv.get("routes", []), "errors": srv.get("errors")})
    return out


def run(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return None, res.stderr.strip()
    return res.stdout, None


def main():
    caddy, zeroserve, fixtures = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    failures = 0
    total = 0
    for fixture in sorted(fixtures.glob("*.caddy")):
        total += 1
        caddy_out, err = run([caddy, "adapt", "--config", str(fixture), "--adapter", "caddyfile"])
        if caddy_out is None:
            print(f"SKIP {fixture.name}: caddy adapt failed: {err}")
            continue
        mine_out, err = run([zeroserve, "--adapt-caddyfile", str(fixture)])
        if mine_out is None:
            print(f"FAIL {fixture.name}: zeroserve adapt failed: {err}")
            failures += 1
            continue
        try:
            caddy_routes = routes_of(json.loads(caddy_out))
            mine_routes = routes_of(json.loads(mine_out))
        except json.JSONDecodeError as e:
            print(f"FAIL {fixture.name}: invalid JSON: {e}")
            failures += 1
            continue
        if caddy_routes == mine_routes:
            print(f"PASS {fixture.name}")
        else:
            failures += 1
            print(f"FAIL {fixture.name}: route trees differ")
            print("  --- caddy ---")
            print("  " + json.dumps(caddy_routes, indent=2).replace("\n", "\n  "))
            print("  --- zeroserve ---")
            print("  " + json.dumps(mine_routes, indent=2).replace("\n", "\n  "))
    print(f"\n{total - failures}/{total} fixtures match")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
