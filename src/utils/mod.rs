pub mod clipboard;

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// In-memory rate limiter for authentication attempts.
pub struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts_per_minute: u32) -> Self {
        RateLimiter {
            attempts: HashMap::new(),
            max_attempts: max_attempts_per_minute,
            window: Duration::from_secs(60),
        }
    }

    /// Record an attempt for a given key.
    /// Returns the remaining attempts. Returns None if rate limited.
    pub fn record_attempt(&mut self, key: &str) -> u32 {
        let now = Instant::now();
        let entries = self.attempts.entry(key.to_string()).or_default();

        // Remove expired entries
        entries.retain(|t| now.duration_since(*t) < self.window);

        entries.push(now);

        let count = entries.len() as u32;
        self.max_attempts.saturating_sub(count)
    }

    /// Check remaining attempts without recording.
    pub fn remaining_attempts(&self, key: &str) -> u32 {
        let now = Instant::now();
        if let Some(entries) = self.attempts.get(key) {
            let active: Vec<_> = entries
                .iter()
                .filter(|t| now.duration_since(**t) < self.window)
                .collect();
            let count = active.len() as u32;
            self.max_attempts.saturating_sub(count)
        } else {
            self.max_attempts
        }
    }

    /// Reset attempts for a key.
    pub fn reset(&mut self, key: &str) {
        self.attempts.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3);
        
        assert_eq!(limiter.record_attempt("user"), 2);
        assert_eq!(limiter.record_attempt("user"), 1);
        assert_eq!(limiter.record_attempt("user"), 0);
        assert_eq!(limiter.record_attempt("user"), 0); // rate limited
        
        // Different key not affected
        assert_eq!(limiter.remaining_attempts("other"), 3);
    }
}
