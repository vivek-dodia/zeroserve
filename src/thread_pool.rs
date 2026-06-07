use std::sync::LazyLock;

/// Process-global pool for blocking CPU work (eBPF program compilation, etc.).
/// Shared by every worker event loop so that compilation across all threads is
/// bounded by the host's parallelism rather than spawning one pool per thread.
pub static CPU_TP: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("cpu-tp-{}", i))
        .num_threads(threads)
        .build()
        .unwrap()
});

/// Process-global pool for blocking DNS resolution (reverse-proxy upstreams).
pub static DNS_TP: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("dns-tp-{}", i))
        .num_threads(4)
        .build()
        .unwrap()
});
