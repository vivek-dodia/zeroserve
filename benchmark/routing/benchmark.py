#!/usr/bin/env python3
"""
Routing/matching benchmark for the Caddy-generated middleware.

Generates a synthetic Caddyfile with N virtual hosts (each with path routes and
a path_regexp route), starts `zeroserve --caddy` in the background, and drives
it with wrk against representative hosts:

  - first   : host that sorts first in the route chain (best case)
  - last    : host that sorts last (worst case: walks every host matcher)
  - last-re : regexp route on the last host (regex matching cost)
  - miss    : host that matches nothing (full walk, 200 {} fallback)

Thread budget (dev machine has 8 fast cores): server --threads 3, wrk -t2.

Usage:
  benchmark/routing/benchmark.py --label baseline [--sites 256] [--duration 3]

Results are printed as a table and appended as JSON lines to
benchmark/routing/results.jsonl with the given label.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "target/release/zeroserve"
WORKDIR = Path("/tmp/zeroserve-bench-routing")
PORT = 18080
SERVER_THREADS = 3
WRK_THREADS = 2
WRK_CONNECTIONS = 64


def gen_caddyfile(n_sites: int) -> str:
    """N http-only vhosts; same-length hostnames so specificity sort keeps
    input order and host{n-1} is deterministically the last route."""
    blocks = []
    for i in range(n_sites):
        host = f"host{i:04d}.bench"
        blocks.append(f"""\
http://{host}:{PORT} {{
    @api path /api/*
    respond @api "api {i}" 200

    @item path_regexp item ^/items/([a-z0-9-]+)$
    respond @item "item {i}" 200

    handle /static/* {{
        respond "static {i}" 200
    }}

    respond "root {i}" 200
}}
""")
    return "\n".join(blocks)


def wait_ready(host: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{PORT}/", headers={"Host": host}
            )
            with urllib.request.urlopen(req, timeout=1) as resp:
                resp.read()
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.2)
    raise RuntimeError(f"server did not become ready: {last_err}")


def check_response(host: str, path: str, expect: str):
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}", headers={"Host": host}
    )
    with urllib.request.urlopen(req, timeout=2) as resp:
        body = resp.read().decode()
    if body != expect:
        raise RuntimeError(
            f"unexpected response for {host}{path}: {body!r} != {expect!r}"
        )


def run_wrk(host: str, path: str, duration: int) -> dict:
    out = subprocess.run(
        [
            "wrk",
            f"-t{WRK_THREADS}",
            f"-c{WRK_CONNECTIONS}",
            f"-d{duration}s",
            "--latency",
            "-H",
            f"Host: {host}",
            f"http://127.0.0.1:{PORT}{path}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    p50 = re.search(r"50%\s+([\d.]+\w+)", out).group(1)
    p99 = re.search(r"99%\s+([\d.]+\w+)", out).group(1)
    return {"rps": rps, "p50": p50, "p99": p99}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--sites", type=int, default=256)
    ap.add_argument("--duration", type=int, default=3)
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument(
        "--server",
        choices=["zeroserve", "caddy"],
        default="zeroserve",
        help="serve the config with zeroserve or stock Caddy",
    )
    ap.add_argument(
        "--caddy-binary",
        default=str(WORKDIR / "caddy-stock"),
        help="stock caddy binary for --server caddy",
    )
    args = ap.parse_args()

    if args.server == "zeroserve" and not BINARY.exists():
        sys.exit(f"missing {BINARY}; run cargo build --release first")

    WORKDIR.mkdir(parents=True, exist_ok=True)
    caddyfile = WORKDIR / f"Caddyfile.{args.sites}"
    caddyfile.write_text(gen_caddyfile(args.sites))
    # Stock Caddy gets the same sites plus admin off, so repeated runs do not
    # fight over the admin port. GOMAXPROCS matches zeroserve's --threads.
    caddyfile_stock = WORKDIR / f"Caddyfile.{args.sites}.stock"
    caddyfile_stock.write_text("{\n    admin off\n}\n\n" + gen_caddyfile(args.sites))

    first = "host0000.bench"
    last = f"host{args.sites - 1:04d}.bench"

    scenarios = [
        ("first", first, "/api/x"),
        ("last", last, "/api/x"),
        ("last-re", last, "/items/abc-123"),
        ("miss", "nomatch.bench", "/api/x"),
    ]

    if args.server == "caddy":
        cmd = [
            args.caddy_binary,
            "run",
            "--config",
            str(caddyfile_stock),
            "--adapter",
            "caddyfile",
        ]
        env = {**os.environ, "GOMAXPROCS": str(SERVER_THREADS)}
    else:
        cmd = [
            str(BINARY),
            "--caddy",
            str(caddyfile),
            "--addr",
            f"127.0.0.1:{PORT}",
            "--threads",
            str(SERVER_THREADS),
        ]
        env = None
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
    )
    results = {}
    try:
        wait_ready(first)
        # Sanity: routing must be correct before we measure it.
        check_response(first, "/api/x", "api 0")
        check_response(last, "/api/x", f"api {args.sites - 1}")
        check_response(last, "/items/abc-123", f"item {args.sites - 1}")
        check_response(last, "/static/a.css", f"static {args.sites - 1}")
        check_response(last, "/", f"root {args.sites - 1}")
        check_response("nomatch.bench", "/api/x", "")

        for name, host, path in scenarios:
            run_wrk(host, path, 1)  # warmup
            best = None
            for _ in range(args.runs):
                r = run_wrk(host, path, args.duration)
                if best is None or r["rps"] > best["rps"]:
                    best = r
            results[name] = best
            print(
                f"{name:8s} {host:18s} {path:16s} "
                f"{best['rps']:>12.0f} req/s  p50 {best['p50']:>8s}  p99 {best['p99']:>8s}"
            )
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()

    record = {
        "label": args.label,
        "server": args.server,
        "sites": args.sites,
        "duration": args.duration,
        "results": results,
    }
    with open(Path(__file__).parent / "results.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    main()
