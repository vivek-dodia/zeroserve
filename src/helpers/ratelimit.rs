use async_ebpf::program::HelperScope;

use crate::script::with_ectx;

/// Helper function: zs_rate_limit
///
/// Check rate limit for a key with per-second, per-minute, and per-hour limits.
///
/// Arguments:
///   key_ptr, key_len - Pointer and length of the key (arbitrary bytes)
///   per_second       - Max requests per second (0 = unlimited)
///   per_minute       - Max requests per minute (0 = unlimited)
///   per_hour         - Max requests per hour (0 = unlimited)
///
/// Returns:
///   0 = allowed
///   1 = per-second limit exceeded
///   2 = per-minute limit exceeded
///   3 = per-hour limit exceeded
///  -1 = error (invalid parameters or key too long)
pub fn h_rate_limit(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    per_second: u64,
    per_minute: u64,
    per_hour: u64,
) -> Result<u64, ()> {
    // Validate key length (reasonable limit to prevent abuse)
    const MAX_KEY_LEN: u64 = 256;
    if key_len == 0 || key_len > MAX_KEY_LEN {
        return Ok(u64::MAX); // Return -1 as error indicator
    }

    // Read key from script memory
    let key = match scope.user_memory(key_ptr, key_len) {
        Ok(k) => k.to_vec(),
        Err(_) => return Ok(u64::MAX),
    };

    with_ectx(scope, |ctx| {
        let result = ctx
            .site
            .rate_limit_manager
            .check(&key, per_second, per_minute, per_hour);
        Ok(result as u64)
    })
}
