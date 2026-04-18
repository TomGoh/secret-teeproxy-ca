//! Time abstraction for testability.
//!
//! Currently unused by production code. Landed as a forward-looking
//! hook for features that need to reason about time — idle-timeout
//! enforcement on HTTP connections, watchdog heartbeats, admin token
//! rotation expiry. Production code that wants to sleep or compare
//! timestamps should reach for the trait so unit tests can advance
//! `MockClock::advance(Duration)` deterministically instead of
//! sprinkling real `thread::sleep` calls.
//!
//! Pre-landed (rather than added lazily per feature) to avoid a
//! per-feature "should we use SystemClock or mock?" debate.

use std::time::{Duration, Instant};

/// Abstract clock. Production: [`SystemClock`]. Tests: [`MockClock`].
pub trait Clock: Send + Sync {
    /// A monotonic "now" — used for timeouts / deadlines. Maps to
    /// `Instant::now()` in production.
    fn now(&self) -> Instant;
    /// Block for approximately `d`. Maps to `std::thread::sleep(d)`
    /// in production; `MockClock` just advances its internal time.
    fn sleep(&self, d: Duration);
}

/// Production [`Clock`] — delegates to std.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(any(test, feature = "test-support"))]
mod mock {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic [`Clock`] for tests. Starts at a fixed `Instant`
    /// (captured at construction). `sleep(d)` does not block — it
    /// just advances the internal time. `advance(d)` is the same;
    /// both names are provided so tests read naturally.
    pub struct MockClock {
        // Interior mutability so `sleep(&self, _)` can shift time
        // without requiring the trait method to take `&mut self`.
        state: Mutex<Instant>,
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockClock {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(Instant::now()),
            }
        }

        pub fn advance(&self, d: Duration) {
            let mut guard = self.state.lock().expect("clock mutex");
            *guard += d;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            *self.state.lock().expect("clock mutex")
        }
        fn sleep(&self, d: Duration) {
            self.advance(d);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use mock::MockClock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_now_is_monotonic_under_advance() {
        let clk = MockClock::new();
        let t0 = clk.now();
        clk.advance(Duration::from_millis(100));
        let t1 = clk.now();
        assert!(
            t1 - t0 >= Duration::from_millis(100),
            "advance must move time forward"
        );
    }

    #[test]
    fn mock_clock_sleep_does_not_block() {
        let clk = MockClock::new();
        let start = std::time::Instant::now();
        clk.sleep(Duration::from_secs(10));
        // Real wall clock should barely move — sleep is a no-op.
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "MockClock::sleep must not block on real time"
        );
    }
}
