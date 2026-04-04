//! Multi-core coordination for the per-CPU scheduler.
//!
//! v1 is a cooperative model -- no lock-free work stealing yet.
//! The coordinator tracks which CPUs are online, idle, and which
//! partition (if any) each CPU is currently executing.

use rvm_types::{PartitionId, RvmError, RvmResult};

/// State of a single physical CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpuState {
    /// Physical CPU identifier.
    pub cpu_id: u8,
    /// Whether this CPU has been brought online.
    pub online: bool,
    /// The partition currently executing on this CPU, if any.
    pub current_partition: Option<PartitionId>,
    /// Whether this CPU is idle (no partition assigned).
    pub idle: bool,
    /// Cumulative epoch ticks processed by this CPU.
    pub epoch_ticks: u64,
}

impl CpuState {
    /// Create a new offline CPU state.
    const fn offline(cpu_id: u8) -> Self {
        Self {
            cpu_id,
            online: false,
            current_partition: None,
            idle: true,
            epoch_ticks: 0,
        }
    }
}

/// Multi-core coordination hub.
///
/// Tracks CPU lifecycle (online/offline), partition assignment, and
/// provides hints for load balancing.
///
/// # Type Parameters
///
/// * `MAX_CPUS` -- maximum number of physical CPUs supported.
pub struct SmpCoordinator<const MAX_CPUS: usize> {
    cpu_states: [CpuState; MAX_CPUS],
}

impl<const MAX_CPUS: usize> SmpCoordinator<MAX_CPUS> {
    /// Create a new coordinator with `cpu_count` CPUs, all initially offline.
    ///
    /// `cpu_count` is clamped to `MAX_CPUS`.
    #[must_use]
    pub fn new(_cpu_count: u8) -> Self {
        let mut states = [CpuState::offline(0); MAX_CPUS];
        for i in 0..MAX_CPUS {
            states[i].cpu_id = i as u8;
        }
        Self {
            cpu_states: states,
        }
    }

    /// Bring a CPU online, making it available for partition assignment.
    ///
    /// # Errors
    ///
    /// * [`RvmError::ResourceLimitExceeded`] -- `cpu_id` is out of range.
    /// * [`RvmError::InvalidPartitionState`] -- CPU is already online.
    pub fn bring_online(&mut self, cpu_id: u8) -> RvmResult<()> {
        let state = self
            .get_state_mut(cpu_id)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if state.online {
            return Err(RvmError::InvalidPartitionState);
        }
        state.online = true;
        state.idle = true;
        state.current_partition = None;
        Ok(())
    }

    /// Take a CPU offline. The CPU must not have an active partition.
    ///
    /// # Errors
    ///
    /// * [`RvmError::ResourceLimitExceeded`] -- `cpu_id` is out of range.
    /// * [`RvmError::InvalidPartitionState`] -- CPU is not online, or has an
    ///   active partition (call [`release_partition`](Self::release_partition) first).
    pub fn take_offline(&mut self, cpu_id: u8) -> RvmResult<()> {
        let state = self
            .get_state_mut(cpu_id)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if !state.online {
            return Err(RvmError::InvalidPartitionState);
        }
        if state.current_partition.is_some() {
            return Err(RvmError::InvalidPartitionState);
        }
        state.online = false;
        state.idle = true;
        Ok(())
    }

    /// Assign a partition to a CPU.
    ///
    /// The CPU must be online and idle.
    ///
    /// # Errors
    ///
    /// * [`RvmError::ResourceLimitExceeded`] -- `cpu_id` is out of range.
    /// * [`RvmError::InvalidPartitionState`] -- CPU is offline or already busy.
    pub fn assign_partition(
        &mut self,
        cpu_id: u8,
        partition: PartitionId,
    ) -> RvmResult<()> {
        let state = self
            .get_state_mut(cpu_id)
            .ok_or(RvmError::ResourceLimitExceeded)?;
        if !state.online {
            return Err(RvmError::InvalidPartitionState);
        }
        if state.current_partition.is_some() {
            return Err(RvmError::InvalidPartitionState);
        }
        state.current_partition = Some(partition);
        state.idle = false;
        state.epoch_ticks = state.epoch_ticks.saturating_add(1);
        Ok(())
    }

    /// Release the partition running on a CPU, returning it to the idle pool.
    ///
    /// Returns the previously assigned partition, or `None` if the CPU was
    /// already idle.
    pub fn release_partition(&mut self, cpu_id: u8) -> Option<PartitionId> {
        let state = self.get_state_mut(cpu_id)?;
        let prev = state.current_partition.take();
        if prev.is_some() {
            state.idle = true;
        }
        prev
    }

    /// Find the first idle, online CPU.
    #[must_use]
    pub fn find_idle_cpu(&self) -> Option<u8> {
        self.cpu_states
            .iter()
            .find(|s| s.online && s.idle)
            .map(|s| s.cpu_id)
    }

    /// Return which CPU is currently running the given partition, if any.
    #[must_use]
    pub fn partition_affinity(&self, partition: PartitionId) -> Option<u8> {
        self.cpu_states
            .iter()
            .find(|s| s.online && s.current_partition == Some(partition))
            .map(|s| s.cpu_id)
    }

    /// Return the number of online CPUs.
    #[must_use]
    pub fn active_count(&self) -> u8 {
        self.cpu_states
            .iter()
            .filter(|s| s.online)
            .count() as u8
    }

    /// Provide a rebalance hint: `(overloaded_cpu, idle_cpu)`.
    ///
    /// The "overloaded" CPU is the online, busy CPU with the most epoch
    /// ticks. The "idle" CPU is any online idle CPU. Returns `None` if
    /// no rebalance opportunity exists.
    #[must_use]
    pub fn rebalance_hint(&self) -> Option<(u8, u8)> {
        let idle_cpu = self.find_idle_cpu()?;
        let overloaded = self
            .cpu_states
            .iter()
            .filter(|s| s.online && s.current_partition.is_some())
            .max_by_key(|s| s.epoch_ticks)?;
        Some((overloaded.cpu_id, idle_cpu))
    }

    /// Return a reference to a CPU's state.
    #[must_use]
    pub fn cpu_state(&self, cpu_id: u8) -> Option<&CpuState> {
        self.cpu_states.get(cpu_id as usize)
    }

    // --- private ---

    fn get_state_mut(&mut self, cpu_id: u8) -> Option<&mut CpuState> {
        self.cpu_states.get_mut(cpu_id as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(id: u32) -> PartitionId {
        PartitionId::new(id)
    }

    // --- Online / Offline ---

    #[test]
    fn test_new_all_offline() {
        let coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        assert_eq!(coord.active_count(), 0);
        for i in 0..4u8 {
            let state = coord.cpu_state(i).unwrap();
            assert!(!state.online);
        }
    }

    #[test]
    fn test_bring_online() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        assert_eq!(coord.active_count(), 1);
        assert!(coord.cpu_state(0).unwrap().online);
        assert!(coord.cpu_state(0).unwrap().idle);
    }

    #[test]
    fn test_bring_online_already_online() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        let result = coord.bring_online(0);
        assert_eq!(result, Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_take_offline() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(1).unwrap();
        coord.take_offline(1).unwrap();
        assert_eq!(coord.active_count(), 0);
        assert!(!coord.cpu_state(1).unwrap().online);
    }

    #[test]
    fn test_take_offline_already_offline() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        let result = coord.take_offline(0);
        assert_eq!(result, Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_take_offline_with_partition_fails() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.assign_partition(0, pid(1)).unwrap();

        let result = coord.take_offline(0);
        assert_eq!(result, Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_out_of_range_cpu() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        assert_eq!(coord.bring_online(99), Err(RvmError::ResourceLimitExceeded));
        assert_eq!(coord.take_offline(99), Err(RvmError::ResourceLimitExceeded));
        assert_eq!(
            coord.assign_partition(99, pid(1)),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    // --- Assign / Release ---

    #[test]
    fn test_assign_and_release() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.assign_partition(0, pid(10)).unwrap();

        assert!(!coord.cpu_state(0).unwrap().idle);
        assert_eq!(coord.cpu_state(0).unwrap().current_partition, Some(pid(10)));

        let released = coord.release_partition(0);
        assert_eq!(released, Some(pid(10)));
        assert!(coord.cpu_state(0).unwrap().idle);
        assert_eq!(coord.cpu_state(0).unwrap().current_partition, None);
    }

    #[test]
    fn test_assign_offline_cpu_fails() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        let result = coord.assign_partition(0, pid(1));
        assert_eq!(result, Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_double_assign_fails() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.assign_partition(0, pid(1)).unwrap();

        let result = coord.assign_partition(0, pid(2));
        assert_eq!(result, Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_release_idle_cpu_returns_none() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        let released = coord.release_partition(0);
        assert_eq!(released, None);
    }

    // --- Find idle ---

    #[test]
    fn test_find_idle_cpu() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.bring_online(1).unwrap();
        coord.assign_partition(0, pid(1)).unwrap();

        // CPU 0 is busy, CPU 1 is idle.
        assert_eq!(coord.find_idle_cpu(), Some(1));
    }

    #[test]
    fn test_find_idle_cpu_none_available() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.assign_partition(0, pid(1)).unwrap();

        // Only CPU 0 is online, and it's busy. CPUs 1-3 are offline.
        assert_eq!(coord.find_idle_cpu(), None);
    }

    // --- Partition affinity ---

    #[test]
    fn test_partition_affinity() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(2).unwrap();
        coord.assign_partition(2, pid(42)).unwrap();

        assert_eq!(coord.partition_affinity(pid(42)), Some(2));
        assert_eq!(coord.partition_affinity(pid(99)), None);
    }

    // --- Rebalance hint ---

    #[test]
    fn test_rebalance_hint() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.bring_online(1).unwrap();

        // Assign and release multiple times to build epoch_ticks on CPU 0.
        for i in 0..5u32 {
            coord.assign_partition(0, pid(i)).unwrap();
            coord.release_partition(0);
        }
        // Assign once more to make CPU 0 busy.
        coord.assign_partition(0, pid(100)).unwrap();

        // CPU 0 is overloaded (5 epoch ticks), CPU 1 is idle.
        let hint = coord.rebalance_hint();
        assert_eq!(hint, Some((0, 1)));
    }

    #[test]
    fn test_rebalance_hint_no_idle() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.assign_partition(0, pid(1)).unwrap();

        // No idle CPU available.
        assert_eq!(coord.rebalance_hint(), None);
    }

    #[test]
    fn test_rebalance_hint_no_busy() {
        let mut coord: SmpCoordinator<4> = SmpCoordinator::new(4);
        coord.bring_online(0).unwrap();
        coord.bring_online(1).unwrap();

        // All CPUs idle -- no overloaded CPU.
        assert_eq!(coord.rebalance_hint(), None);
    }

    // --- Max CPUs ---

    #[test]
    fn test_max_cpus_boundary() {
        let mut coord: SmpCoordinator<2> = SmpCoordinator::new(2);
        coord.bring_online(0).unwrap();
        coord.bring_online(1).unwrap();
        assert_eq!(coord.active_count(), 2);

        // CPU 2 does not exist.
        assert_eq!(coord.bring_online(2), Err(RvmError::ResourceLimitExceeded));
    }
}
