# Zeroserve Memory Benchmark Report

This report documents the memory efficiency of running multiple concurrent zeroserve instances under load.

## Test Configuration

| Parameter         | Value                                                   |
| ----------------- | ------------------------------------------------------- |
| Instances         | 1,000                                                   |
| Site tarball size | 100 MB                                                  |
| Middleware        | Userspace eBPF script (health endpoint + custom header) |
| Load generator    | wrk -t2 -c10 -d1s per instance                          |
| Load pattern      | All 1,000 instances hit concurrently                    |

### Scripting Runtime

Zeroserve uses the `async-ebpf` crate to execute eBPF bytecode entirely in **userspace**—no kernel eBPF subsystem is involved. Scripts are:

1. **Compiled** with clang/llc to eBPF object files (`-target bpf -march=bpf -mcpu=v3`)
2. **Loaded** into a userspace VM at startup via `async-ebpf`'s `ProgramLoader`
3. **Executed** per-request with async preemption and timeslicing

Each request receives a dedicated `ScriptExecutionContext` with:

- Per-request metadata map shared across script chain
- External object registry (max 32 handles for JSON objects, etc.)
- Memory footprint tracking with configurable limits (default 256 KB)
- Lazy body loading

The runtime enforces timeslicing (yields after 1ms, throttles after 20ms) to prevent scripts from blocking the async executor.

## Methodology

### Memory Measurement

Summing RSS (Resident Set Size) across processes is **incorrect** for measuring total memory consumption because it double-counts shared memory (e.g., the zeroserve binary and shared libraries loaded by each process). Instead, we use:

1. **PSS (Proportional Set Size)**: Divides shared memory proportionally among all processes sharing it. Read from `/proc/[pid]/smaps`.

2. **System-wide consumption**: Difference in `MemAvailable` from `/proc/meminfo` before and after starting instances.

### Test Procedure

1. Record baseline `MemAvailable`
2. Start 1,000 zeroserve instances on consecutive ports (10000-10999)
3. Wait for initialization
4. Measure memory before load
5. Launch 1,000 concurrent wrk processes (one per instance, 1 second each)
6. Sample memory at 50ms intervals during load to capture peak
7. Record final memory measurements

## Results

### Startup Performance

| Metric                         | Value                |
| ------------------------------ | -------------------- |
| Time to start 1,000 instances  | 4.76s                |
| Instances successfully started | 1,000 / 1,000 (100%) |
| Load test duration             | 5.83s                |

### Memory Before Load

| Metric         | Total       | Per-instance |
| -------------- | ----------- | ------------ |
| PSS (correct)  | 717.08 MB   | 734 KB       |
| RSS (inflated) | 4,966.69 MB | 5,086 KB     |

### Peak Memory During Load

| Metric            | Total           | Per-instance |
| ----------------- | --------------- | ------------ |
| **PSS (correct)** | **1,160.84 MB** | **1,189 KB** |
| RSS (inflated)    | 5,503.65 MB     | 5,636 KB     |
| System consumed   | 1,581.08 MB     | 1,619 KB     |

### Shared Memory Efficiency

| Metric        | Value       |
| ------------- | ----------- |
| RSS overcount | 4,342.81 MB |
| Sharing ratio | 4.74x       |

The RSS measurement would incorrectly suggest ~5.5 GB of memory usage, while actual consumption is ~1.16 GB—a 4.74x difference due to shared memory.

## Analysis

### Per-Instance Overhead

Under load with a 100 MB site tarball and active userspace eBPF middleware:

- **~1.2 MB per instance** (PSS)
- Memory growth during load: ~455 KB per instance (from 734 KB idle to 1,189 KB under load)

### Memory Efficiency

The low per-instance overhead is achieved through:

1. **Shared binary mappings**: The zeroserve executable and linked libraries are shared across all instances via the OS page cache
2. **Metadata-only indexing**: Only tarball metadata is held in memory (~100 bytes per file: path, byte offset, size, ETag, mtime). The 100 MB tarball's file content is never loaded into memory.
3. **Streaming with positional reads**: File content is served on-demand via `read_at()` at the entry's byte offset, streamed in configurable chunks (default 64 KB) directly to the socket
4. **Thread-local file handle cache**: Each thread maintains its own cloned file descriptor, enabling concurrent reads without contention
5. **Compact script runtime**: The userspace eBPF VM (`async-ebpf`) has minimal overhead; compiled scripts are small (the test script is 1,824 bytes) and per-request context is bounded

### Scalability Projection

Based on these results, approximate memory requirements for larger deployments:

| Instances | Estimated PSS | Notes     |
| --------- | ------------- | --------- |
| 1,000     | ~1.2 GB       | Measured  |
| 5,000     | ~6 GB         | Projected |
| 10,000    | ~12 GB        | Projected |

## Reproducing the Benchmark

### Prerequisites

- Linux system with `/proc` filesystem
- `wrk` load testing tool
- Built zeroserve binary (`cargo build --release`)
- BPF toolchain (`clang`, `llc`) for script compilation

### Setup

```bash
# Create test site
mkdir -p /tmp/zeroserve-bench/site/.zeroserve/scripts

# Generate 100MB content
dd if=/dev/urandom of=/tmp/zeroserve-bench/site/large-asset.bin bs=1M count=100

# Create index page
echo '<!DOCTYPE html><html><body><h1>Benchmark</h1></body></html>' \
  > /tmp/zeroserve-bench/site/index.html

# Create middleware script
cat > /tmp/zeroserve-bench/site/.zeroserve/scripts/10-middleware.c << 'EOF'
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[128];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/health") == 0) {
        zs_meta_set(ZS_STR("zs.response.header.content-type"),
                    ZS_STR("application/json"));
        zs_respond(200, ZS_STR("{\"status\":\"ok\"}\n"));
    }

    zs_meta_set(ZS_STR("zs.response.header.x-benchmark"), ZS_STR("true"));
    return 0;
}
EOF

# Pack tarball (compiles .c scripts to .o)
./target/release/zeroserve --pack /tmp/zeroserve-bench/site \
  > /tmp/zeroserve-bench/site.tar
```

### Run Benchmark

Save the benchmark script `benchmark.py` as `/tmp/zeroserve-bench/benchmark.py` and run:

```bash
python3 /tmp/zeroserve-bench/benchmark.py
```

## Conclusion

Zeroserve demonstrates efficient memory utilization when running many concurrent instances:

- **Peak memory: 1.16 GB** for 1,000 instances under concurrent load
- **Per-instance overhead: ~1.2 MB** including a 100 MB site tarball and userspace eBPF middleware
- **Shared memory savings: 4.74x** compared to naive RSS summation

The userspace eBPF scripting model (via `async-ebpf`) provides sandboxed request processing with bounded per-request memory allocation and no kernel dependencies, making zeroserve portable and suitable for high-density deployments.
