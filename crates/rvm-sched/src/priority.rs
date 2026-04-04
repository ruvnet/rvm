//! Priority computation: deadline urgency + cut pressure boost.

use rvm_types::CutPressure;

/// Compute the combined priority for a partition.
///
/// `priority = deadline_urgency + cut_pressure_boost`
///
/// Returns a value in [0, 65535]. Higher = more urgent.
#[inline]
#[must_use]
pub fn compute_priority(deadline_urgency: u16, cut_pressure: CutPressure) -> u32 {
    let pressure_boost = (cut_pressure.as_fixed() >> 16).min(u16::MAX as u32) as u16;
    deadline_urgency as u32 + pressure_boost as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_inputs() {
        assert_eq!(compute_priority(0, CutPressure::ZERO), 0);
    }

    #[test]
    fn test_deadline_only() {
        // With zero pressure, priority equals deadline urgency.
        assert_eq!(compute_priority(100, CutPressure::ZERO), 100);
    }

    #[test]
    fn test_pressure_boost() {
        // CutPressure::from_fixed shifts right by 16, so value 0x10000 = boost of 1.
        let pressure = CutPressure::from_fixed(0x0001_0000);
        assert_eq!(compute_priority(100, pressure), 101);
    }

    #[test]
    fn test_combined_signals() {
        let pressure = CutPressure::from_fixed(0x0005_0000); // boost = 5
        assert_eq!(compute_priority(200, pressure), 205);
    }

    #[test]
    fn test_no_overflow() {
        // Maximum deadline + maximum pressure should not overflow.
        let pressure = CutPressure::from_fixed(u32::MAX);
        let result = compute_priority(u16::MAX, pressure);
        assert!(result <= u32::MAX);
    }
}
