//! ARM Generic Timer driver for AArch64 (EL2).
//!
//! Uses the EL2 physical timer (CNTHP) for hypervisor scheduling.
//! The QEMU virt machine provides a standard ARM generic timer
//! with configurable frequency (typically 62.5 MHz on QEMU).

/// Read the timer frequency from CNTFRQ_EL0.
///
/// Returns the frequency in Hz. On QEMU virt this is typically
/// 62,500,000 (62.5 MHz).
#[inline]
pub fn timer_freq() -> u64 {
    let freq: u64;
    // SAFETY: Reading CNTFRQ_EL0 is a pure read with no side effects.
    // The register is readable at all exception levels.
    unsafe {
        core::arch::asm!(
            "mrs {reg}, CNTFRQ_EL0",
            reg = out(reg) freq,
            options(nomem, nostack, preserves_flags),
        );
    }
    freq
}

/// Read the current physical counter value from CNTPCT_EL0.
///
/// Returns the monotonically increasing counter value in ticks.
#[inline]
pub fn timer_current() -> u64 {
    let cnt: u64;
    // SAFETY: Reading CNTPCT_EL0 is a pure read with no side effects.
    // The counter is always accessible.
    unsafe {
        core::arch::asm!(
            "mrs {reg}, CNTPCT_EL0",
            reg = out(reg) cnt,
            options(nomem, nostack, preserves_flags),
        );
    }
    cnt
}

/// Initialize the EL2 physical timer (CNTHP).
///
/// Enables the timer and unmasks the interrupt output, but does not
/// set a deadline. Call [`timer_set_deadline`] to arm the timer.
///
/// The `_freq_hz` parameter is accepted for API symmetry but is not
/// used: the ARM generic timer frequency is hardware-defined.
pub fn timer_init(_freq_hz: u64) {
    // CNTHP_CTL_EL2:
    //   ENABLE (bit 0) = 1: timer enabled
    //   IMASK  (bit 1) = 0: interrupt not masked
    //   ISTATUS (bit 2): read-only
    let ctl: u64 = 1; // ENABLE=1, IMASK=0

    // SAFETY: Writing CNTHP_CTL_EL2 at EL2 configures the hypervisor
    // physical timer. No deadline is set yet, so no interrupt fires.
    unsafe {
        core::arch::asm!(
            "msr CNTHP_CTL_EL2, {val}",
            "isb",
            val = in(reg) ctl,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Set the EL2 physical timer deadline (absolute compare value).
///
/// The timer fires when CNTPCT_EL0 >= `ticks`. The value is an
/// absolute counter value, not a relative delta. Use
/// `timer_current() + delta` to compute a relative deadline.
pub fn timer_set_deadline(ticks: u64) {
    // SAFETY: Writing CNTHP_CVAL_EL2 at EL2 sets the compare value
    // for the hypervisor physical timer. This is the standard way to
    // arm a one-shot timer deadline.
    unsafe {
        core::arch::asm!(
            "msr CNTHP_CVAL_EL2, {val}",
            "isb",
            val = in(reg) ticks,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Disable the EL2 physical timer by masking its interrupt.
///
/// Sets CNTHP_CTL_EL2.IMASK to prevent the timer from generating
/// an interrupt. The timer remains enabled but silent.
pub fn timer_disable() {
    // CNTHP_CTL_EL2: ENABLE=1, IMASK=1
    let ctl: u64 = 1 | (1 << 1);

    // SAFETY: Writing CNTHP_CTL_EL2 to mask the timer interrupt.
    // The timer keeps running but does not fire.
    unsafe {
        core::arch::asm!(
            "msr CNTHP_CTL_EL2, {val}",
            "isb",
            val = in(reg) ctl,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Convert nanoseconds to timer ticks at the given frequency.
///
/// Returns 0 if `freq_hz` is zero (timer not yet initialized).
#[must_use]
pub const fn ns_to_ticks(ns: u64, freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    // ticks = ns * freq / 1_000_000_000
    // Use u128 intermediate to avoid overflow.
    ((ns as u128 * freq_hz as u128) / 1_000_000_000) as u64
}

/// Convert timer ticks to nanoseconds at the given frequency.
///
/// Returns 0 if `freq_hz` is zero (timer not yet initialized).
#[must_use]
pub const fn ticks_to_ns(ticks: u64, freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    // ns = ticks * 1_000_000_000 / freq
    ((ticks as u128 * 1_000_000_000) / freq_hz as u128) as u64
}

/// AArch64 timer implementing the HAL `TimerOps` trait.
pub struct Aarch64Timer {
    /// Cached frequency from CNTFRQ_EL0 (set during init).
    freq_hz: u64,
    /// Whether a deadline is currently active.
    deadline_active: bool,
}

impl Aarch64Timer {
    /// Create a new timer handle (not yet initialized).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            freq_hz: 0,
            deadline_active: false,
        }
    }

    /// Initialize the timer hardware and cache the frequency.
    pub fn init(&mut self) {
        self.freq_hz = timer_freq();
        timer_init(self.freq_hz);
    }

    /// Return the cached timer frequency in Hz.
    #[must_use]
    pub const fn freq(&self) -> u64 {
        self.freq_hz
    }
}

impl crate::TimerOps for Aarch64Timer {
    fn now_ns(&self) -> u64 {
        if self.freq_hz == 0 {
            return 0;
        }
        ticks_to_ns(timer_current(), self.freq_hz)
    }

    fn set_deadline_ns(&mut self, ns_from_now: u64) -> rvm_types::RvmResult<()> {
        if self.freq_hz == 0 {
            return Err(rvm_types::RvmError::InternalError);
        }
        let delta_ticks = ns_to_ticks(ns_from_now, self.freq_hz);
        let deadline = timer_current().saturating_add(delta_ticks);
        timer_set_deadline(deadline);
        self.deadline_active = true;
        Ok(())
    }

    fn cancel_deadline(&mut self) -> rvm_types::RvmResult<()> {
        if !self.deadline_active {
            return Err(rvm_types::RvmError::InternalError);
        }
        timer_disable();
        self.deadline_active = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimerOps;

    #[test]
    fn test_ns_to_ticks() {
        // 1 second at 62.5 MHz = 62_500_000 ticks
        assert_eq!(ns_to_ticks(1_000_000_000, 62_500_000), 62_500_000);
    }

    #[test]
    fn test_ticks_to_ns() {
        // 62_500_000 ticks at 62.5 MHz = 1 second
        assert_eq!(ticks_to_ns(62_500_000, 62_500_000), 1_000_000_000);
    }

    #[test]
    fn test_roundtrip() {
        let freq = 62_500_000u64;
        let ns = 500_000_000u64; // 500ms
        let ticks = ns_to_ticks(ns, freq);
        let result = ticks_to_ns(ticks, freq);
        // Allow rounding error of 1 tick worth of ns.
        let one_tick_ns = 1_000_000_000 / freq;
        assert!((result as i64 - ns as i64).unsigned_abs() <= one_tick_ns);
    }

    #[test]
    fn test_timer_new() {
        let timer = Aarch64Timer::new();
        assert_eq!(timer.freq(), 0);
        assert!(!timer.deadline_active);
    }

    #[test]
    fn test_ns_to_ticks_zero_freq() {
        assert_eq!(ns_to_ticks(1_000_000_000, 0), 0);
    }

    #[test]
    fn test_ticks_to_ns_zero_freq() {
        assert_eq!(ticks_to_ns(62_500_000, 0), 0);
    }

    #[test]
    fn test_cancel_without_deadline_fails() {
        let mut timer = Aarch64Timer::new();
        assert!(timer.cancel_deadline().is_err());
    }
}
