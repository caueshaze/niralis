use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct LoginRateLimiter {
    max_attempts: u32,
    cooldown: Duration,
    failures: HashMap<String, LoginFailureState>,
}

#[derive(Debug, Clone, Copy)]
struct LoginFailureState {
    attempts: u32,
    last_failure: Instant,
}

impl LoginRateLimiter {
    pub(super) fn new(max_attempts: u32, cooldown: Duration) -> Self {
        Self {
            max_attempts,
            cooldown,
            failures: HashMap::new(),
        }
    }

    pub(super) fn is_limited(&mut self, username: &str, now: Instant) -> bool {
        if self.max_attempts == 0 {
            return false;
        }

        let Some(state) = self.failures.get(username).copied() else {
            return false;
        };

        if state.attempts < self.max_attempts {
            return false;
        }

        if now.duration_since(state.last_failure) >= self.cooldown {
            self.failures.remove(username);
            false
        } else {
            true
        }
    }

    pub(super) fn record_failure(&mut self, username: &str, now: Instant) {
        if self.max_attempts == 0 {
            return;
        }

        self.failures
            .entry(username.to_owned())
            .and_modify(|state| {
                state.attempts = state.attempts.saturating_add(1);
                state.last_failure = now;
            })
            .or_insert(LoginFailureState {
                attempts: 1,
                last_failure: now,
            });
    }

    pub(super) fn reset(&mut self, username: &str) {
        self.failures.remove(username);
    }
}
