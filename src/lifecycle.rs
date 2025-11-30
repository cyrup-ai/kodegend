use crate::state_machine::{Action, Event, State, Transition};
use std::time::Instant;

/// Thin, inlineable helper that owns the state enum and
/// returns the side‑effect requested by the transition table.
#[derive(Clone)]
pub struct Lifecycle {
    state: State,
    start_time: Instant,
}
impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: State::Stopped,
            start_time: Instant::now(),
        }
    }
}
impl Lifecycle {
    /// Feed an `Event`, get back an `Action`.
    #[inline(always)]
    pub fn step(&mut self, e: Event) -> Action {
        let (next, act) = Transition::next(self.state, e);
        self.state = next;
        act
    }

    #[inline(always)]
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == State::Running
    }

    /// Get the start time of the lifecycle (when this struct was created)
    #[inline(always)]
    #[must_use]
    pub fn start_time(&self) -> Instant {
        self.start_time
    }
}
