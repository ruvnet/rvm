//! Scheduler operating modes.

/// Scheduler operating mode (ADR-132).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Hard real-time. Bounded local execution only.
    Reflex,
    /// Normal execution with coherence-aware placement.
    Flow,
    /// Stabilization: replay, rollback, split.
    Recovery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_equality() {
        assert_eq!(SchedulerMode::Reflex, SchedulerMode::Reflex);
        assert_ne!(SchedulerMode::Reflex, SchedulerMode::Flow);
    }

    #[test]
    fn test_mode_variants() {
        let modes = [SchedulerMode::Reflex, SchedulerMode::Flow, SchedulerMode::Recovery];
        assert_eq!(modes.len(), 3);
    }
}
