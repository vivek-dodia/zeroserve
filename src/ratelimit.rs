use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// Result of a rate limit check
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed = 0,
    /// Per-second limit exceeded
    ExceededSecond = 1,
    /// Per-minute limit exceeded
    ExceededMinute = 2,
    /// Per-hour limit exceeded
    ExceededHour = 3,
    /// Bucket limit exceeded (too many unique keys)
    ExceededBucketLimit = 4,
}

/// A rate limit bucket tracking counts for different time windows
#[derive(Debug, Clone)]
struct RateLimitBucket {
    /// Current second timestamp (Unix timestamp / 1)
    second_ts: u64,
    /// Request count in current second
    second_count: u64,
    /// Current minute timestamp (Unix timestamp / 60)
    minute_ts: u64,
    /// Request count in current minute
    minute_count: u64,
    /// Current hour timestamp (Unix timestamp / 3600)
    hour_ts: u64,
    /// Request count in current hour
    hour_count: u64,
}

impl RateLimitBucket {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            second_ts: now,
            second_count: 0,
            minute_ts: now / 60,
            minute_count: 0,
            hour_ts: now / 3600,
            hour_count: 0,
        }
    }
}

/// Manages rate limiting across all requests
pub struct RateLimitManager {
    buckets: DashMap<Vec<u8>, RateLimitBucket>,
    max_buckets: usize,
}

impl RateLimitManager {
    pub fn new(max_buckets: usize) -> Self {
        Self {
            buckets: DashMap::new(),
            max_buckets,
        }
    }

    /// Check rate limit for a key and increment counters if allowed
    pub fn check(
        &self,
        key: &[u8],
        per_second: u64,
        per_minute: u64,
        per_hour: u64,
    ) -> RateLimitResult {
        // Validate limits (0 means unlimited)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let current_second = now;
        let current_minute = now / 60;
        let current_hour = now / 3600;

        // Check if this would be a new entry and if we're at the limit
        let is_new_entry = !self.buckets.contains_key(key);
        if is_new_entry && self.buckets.len() >= self.max_buckets {
            return RateLimitResult::ExceededBucketLimit;
        }

        // Use entry API for atomic update
        let entry = self.buckets.entry(key.to_vec());

        let mut bucket = entry.or_insert_with(RateLimitBucket::new);

        // Reset counters if time windows have changed
        if bucket.second_ts != current_second {
            bucket.second_ts = current_second;
            bucket.second_count = 0;
        }
        if bucket.minute_ts != current_minute {
            bucket.minute_ts = current_minute;
            bucket.minute_count = 0;
        }
        if bucket.hour_ts != current_hour {
            bucket.hour_ts = current_hour;
            bucket.hour_count = 0;
        }

        // Check limits before incrementing
        if per_second > 0 && bucket.second_count >= per_second {
            return RateLimitResult::ExceededSecond;
        }
        if per_minute > 0 && bucket.minute_count >= per_minute {
            return RateLimitResult::ExceededMinute;
        }
        if per_hour > 0 && bucket.hour_count >= per_hour {
            return RateLimitResult::ExceededHour;
        }

        // Increment counters
        bucket.second_count += 1;
        bucket.minute_count += 1;
        bucket.hour_count += 1;

        RateLimitResult::Allowed
    }

    /// Clean up expired buckets to prevent unbounded memory growth
    /// Should be called periodically from a background task
    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let current_hour = now / 3600;

        // Remove buckets that haven't been used in the current hour
        // (since hour is the largest window we track)
        self.buckets
            .retain(|_, bucket| bucket.hour_ts == current_hour);
    }
}
