#!/usr/bin/env python3
"""
Zeroserve benchmark: Start 1000 instances, hit each with wrk, measure peak memory.
Uses PSS (Proportional Set Size) for correct memory accounting with shared memory.
"""

import subprocess
import time
import os
import signal
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

ZEROSERVE = "./target/release/zeroserve"
TARBALL = "/tmp/zeroserve-bench/site.tar"
NUM_INSTANCES = 1000
BASE_PORT = 10000
WRK_DURATION = "1s"
WRK_THREADS = 2
WRK_CONNECTIONS = 10

processes = []
peak_memory = {"pss": 0, "rss": 0, "consumed": 0}
peak_lock = threading.Lock()
baseline_available = 0
stop_monitoring = threading.Event()


def get_pss_kb(pid):
    """Get PSS (Proportional Set Size) for a process - correct for shared memory."""
    try:
        total = 0
        with open(f"/proc/{pid}/smaps", "r") as f:
            for line in f:
                if line.startswith("Pss:"):
                    total += int(line.split()[1])
        return total
    except (FileNotFoundError, PermissionError):
        return 0


def get_rss_kb(pid):
    """Get RSS for a process - overcounts shared memory."""
    try:
        with open(f"/proc/{pid}/statm", "r") as f:
            pages = int(f.read().split()[1])
            return pages * 4  # 4KB pages
    except (FileNotFoundError, PermissionError):
        return 0


def get_mem_available_kb():
    """Get system MemAvailable from /proc/meminfo."""
    with open("/proc/meminfo", "r") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    return 0


def get_total_memory():
    """Get total PSS and RSS for all zeroserve processes."""
    total_pss = 0
    total_rss = 0
    for proc in processes:
        if proc.poll() is None:  # Still running
            total_pss += get_pss_kb(proc.pid)
            total_rss += get_rss_kb(proc.pid)
    return total_pss, total_rss


def memory_monitor():
    """Background thread to track peak memory usage."""
    global peak_memory
    while not stop_monitoring.is_set():
        pss, rss = get_total_memory()
        available = get_mem_available_kb()
        consumed = baseline_available - available

        with peak_lock:
            if pss > peak_memory["pss"]:
                peak_memory["pss"] = pss
            if rss > peak_memory["rss"]:
                peak_memory["rss"] = rss
            if consumed > peak_memory["consumed"]:
                peak_memory["consumed"] = consumed

        time.sleep(0.05)  # 50ms sampling


def run_wrk(port):
    """Run wrk against a single instance."""
    try:
        subprocess.run(
            ["wrk", f"-t{WRK_THREADS}", f"-c{WRK_CONNECTIONS}", f"-d{WRK_DURATION}",
             f"http://127.0.0.1:{port}/"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        return True
    except Exception as e:
        return False


def cleanup():
    """Kill all zeroserve processes."""
    print("Cleaning up...")
    for proc in processes:
        try:
            proc.terminate()
        except:
            pass
    time.sleep(0.5)
    for proc in processes:
        try:
            proc.kill()
        except:
            pass
    print("Cleanup complete.")


def main():
    global baseline_available, processes

    print(f"=== Zeroserve Benchmark: {NUM_INSTANCES} instances ===")
    tarball_size = os.path.getsize(TARBALL) / (1024 * 1024)
    print(f"Tarball: {TARBALL} ({tarball_size:.1f} MB)")
    print()

    # Record baseline memory
    print("Recording baseline memory...")
    baseline_available = get_mem_available_kb()
    print(f"Baseline MemAvailable: {baseline_available} KB")
    print()

    # Start instances
    print(f"Starting {NUM_INSTANCES} zeroserve instances...")
    start_time = time.time()

    for i in range(NUM_INSTANCES):
        port = BASE_PORT + i
        proc = subprocess.Popen(
            [ZEROSERVE, "--addr", f"127.0.0.1:{port}", "--disable-request-logging", TARBALL],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(proc)

        if (i + 1) % 100 == 0:
            print(f"  Started {i + 1} instances...")

    startup_time = time.time() - start_time
    print(f"All instances started in {startup_time:.2f}s")
    print()

    # Wait for instances to initialize
    print("Waiting for instances to initialize...")
    time.sleep(2)

    # Count running instances
    alive_count = sum(1 for p in processes if p.poll() is None)
    print(f"Running instances: {alive_count} / {NUM_INSTANCES}")
    if alive_count < NUM_INSTANCES:
        print("WARNING: Some instances failed to start!")
    print()

    # Memory before load
    print("=== Memory Before Load ===")
    pss_before, rss_before = get_total_memory()
    available_before = get_mem_available_kb()
    consumed_before = baseline_available - available_before

    print(f"Total PSS (correct): {pss_before} KB ({pss_before/1024:.2f} MB)")
    print(f"Total RSS (inflated): {rss_before} KB ({rss_before/1024:.2f} MB)")
    print(f"Per-instance PSS: {pss_before/alive_count:.2f} KB")
    print(f"Memory consumed from baseline: {consumed_before} KB ({consumed_before/1024:.2f} MB)")
    print()

    # Start memory monitoring
    monitor_thread = threading.Thread(target=memory_monitor, daemon=True)
    monitor_thread.start()

    # Run wrk load test
    print(f"=== Running wrk Load Test ({WRK_DURATION} per instance, all concurrent) ===")
    wrk_start = time.time()

    with ThreadPoolExecutor(max_workers=NUM_INSTANCES) as executor:
        futures = [executor.submit(run_wrk, BASE_PORT + i) for i in range(NUM_INSTANCES)]
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 200 == 0:
                print(f"  {completed}/{NUM_INSTANCES} wrk tests completed...")

    wrk_duration = time.time() - wrk_start
    stop_monitoring.set()
    print(f"Load test completed in {wrk_duration:.2f}s")
    print()

    # Memory after load
    print("=== Memory After Load ===")
    pss_after, rss_after = get_total_memory()
    print(f"Total PSS (correct): {pss_after} KB ({pss_after/1024:.2f} MB)")
    print(f"Total RSS (inflated): {rss_after} KB ({rss_after/1024:.2f} MB)")
    print()

    # Final summary
    print("=" * 50)
    print("=== BENCHMARK RESULTS ===")
    print("=" * 50)
    print()
    print("Configuration:")
    print(f"  Instances: {NUM_INSTANCES}")
    print(f"  Site tarball: {tarball_size:.1f} MB")
    print(f"  wrk: -t{WRK_THREADS} -c{WRK_CONNECTIONS} -d{WRK_DURATION}")
    print()
    print("Startup:")
    print(f"  Time to start all instances: {startup_time:.2f}s")
    print(f"  Running instances: {alive_count} / {NUM_INSTANCES}")
    print()
    print("Peak Memory During Load (CORRECT - using PSS):")
    print(f"  Total PSS: {peak_memory['pss']} KB = {peak_memory['pss']/1024:.2f} MB")
    print(f"  Per-instance: {peak_memory['pss']/alive_count:.2f} KB")
    print()
    print("Peak Memory (INCORRECT - using RSS, shown for comparison):")
    print(f"  Total RSS: {peak_memory['rss']} KB = {peak_memory['rss']/1024:.2f} MB")
    print(f"  Per-instance: {peak_memory['rss']/alive_count:.2f} KB")
    print()
    print("System-wide Memory Consumed from Baseline:")
    print(f"  Peak: {peak_memory['consumed']} KB = {peak_memory['consumed']/1024:.2f} MB")
    print(f"  Per-instance: {peak_memory['consumed']/alive_count:.2f} KB")
    print()
    if peak_memory['pss'] > 0:
        print("Shared Memory Savings:")
        print(f"  RSS overcount: {(peak_memory['rss'] - peak_memory['pss'])/1024:.2f} MB")
        print(f"  Sharing ratio: {peak_memory['rss']/peak_memory['pss']:.2f}x")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted!")
    finally:
        cleanup()
