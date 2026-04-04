//! Agent lifecycle management for WASM guests.
//!
//! Per ADR-140: WASM agents run within coherence domain partitions.
//! Each agent has a badge-based identifier and progresses through a
//! well-defined state machine. Every transition emits a witness record.

use rvm_types::{ActionKind, PartitionId, RvmError, RvmResult, WitnessRecord};
use rvm_witness::WitnessLog;

/// Unique identifier for a WASM agent, derived from its capability badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AgentId(u32);

impl AgentId {
    /// Create a new agent identifier from a badge value.
    #[must_use]
    pub const fn from_badge(badge: u32) -> Self {
        Self(badge)
    }

    /// Return the raw badge value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Lifecycle state of a WASM agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is being set up (loading module, validating).
    Initializing,
    /// Agent is actively executing instructions.
    Running,
    /// Agent execution is paused; state is preserved in-place.
    Suspended,
    /// Agent is being transferred to another partition.
    Migrating,
    /// Agent state has been serialized to cold storage.
    Hibernated,
    /// Agent is being restored from a hibernation snapshot.
    Reconstructing,
    /// Agent has been terminated and resources freed.
    Terminated,
}

/// Configuration for spawning a new WASM agent.
#[derive(Debug, Clone, Copy)]
pub struct AgentConfig {
    /// Badge value used to derive the agent identifier.
    pub badge: u32,
    /// Partition that will host this agent.
    pub partition_id: PartitionId,
    /// Maximum memory pages this agent may use.
    pub max_memory_pages: u32,
}

/// A single WASM agent instance within a partition.
#[derive(Debug, Clone, Copy)]
pub struct Agent {
    /// Badge-based identifier.
    pub id: AgentId,
    /// Current lifecycle state.
    pub state: AgentState,
    /// Hosting partition.
    pub partition_id: PartitionId,
    /// Memory pages currently in use.
    pub memory_usage: u32,
    /// Total IPC messages sent and received.
    pub message_count: u64,
}

impl Agent {
    /// Create a new agent in the `Initializing` state.
    #[must_use]
    pub const fn new(id: AgentId, partition_id: PartitionId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            partition_id,
            memory_usage: 0,
            message_count: 0,
        }
    }
}

/// Fixed-size registry of WASM agents within a partition.
///
/// `MAX` is the maximum number of concurrent agents.
pub struct AgentManager<const MAX: usize> {
    agents: [Option<Agent>; MAX],
    count: usize,
}

impl<const MAX: usize> AgentManager<MAX> {
    /// Sentinel value for array init.
    const NONE: Option<Agent> = None;

    /// Create an empty agent manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            agents: [Self::NONE; MAX],
            count: 0,
        }
    }

    /// Return the number of active (non-terminated) agents.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Spawn a new agent from the given configuration.
    ///
    /// Emits a `TaskSpawn` witness record on success.
    pub fn spawn<const W: usize>(
        &mut self,
        config: &AgentConfig,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<AgentId> {
        if self.count >= MAX {
            return Err(RvmError::ResourceLimitExceeded);
        }

        let id = AgentId::from_badge(config.badge);

        // Reject duplicate badges.
        for slot in self.agents.iter() {
            if let Some(agent) = slot {
                if agent.id == id && agent.state != AgentState::Terminated {
                    return Err(RvmError::InternalError);
                }
            }
        }

        let agent = Agent::new(id, config.partition_id);

        for slot in self.agents.iter_mut() {
            if slot.is_none() {
                *slot = Some(agent);
                self.count += 1;
                emit_agent_witness(witness_log, ActionKind::TaskSpawn, config.partition_id, id);
                return Ok(id);
            }
        }

        Err(RvmError::InternalError)
    }

    /// Transition an agent to the `Running` state.
    pub fn activate(&mut self, id: AgentId) -> RvmResult<()> {
        let agent = self.get_mut(id)?;
        match agent.state {
            AgentState::Initializing | AgentState::Reconstructing => {
                agent.state = AgentState::Running;
                Ok(())
            }
            _ => Err(RvmError::InvalidPartitionState),
        }
    }

    /// Suspend a running agent.
    pub fn suspend<const W: usize>(
        &mut self,
        id: AgentId,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<()> {
        let agent = self.get_mut(id)?;
        if agent.state != AgentState::Running {
            return Err(RvmError::InvalidPartitionState);
        }
        let partition_id = agent.partition_id;
        agent.state = AgentState::Suspended;
        emit_agent_witness(witness_log, ActionKind::PartitionSuspend, partition_id, id);
        Ok(())
    }

    /// Resume a suspended agent.
    pub fn resume<const W: usize>(
        &mut self,
        id: AgentId,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<()> {
        let agent = self.get_mut(id)?;
        if agent.state != AgentState::Suspended {
            return Err(RvmError::InvalidPartitionState);
        }
        let partition_id = agent.partition_id;
        agent.state = AgentState::Running;
        emit_agent_witness(witness_log, ActionKind::PartitionResume, partition_id, id);
        Ok(())
    }

    /// Terminate an agent and free its slot.
    ///
    /// The slot is set to `None` so it can be reused by future spawns.
    /// Without this, terminated agents permanently occupy slots and
    /// eventually exhaust the agent capacity (resource exhaustion).
    pub fn terminate<const W: usize>(
        &mut self,
        id: AgentId,
        witness_log: &WitnessLog<W>,
    ) -> RvmResult<()> {
        // Find the slot and extract the info we need before clearing it.
        let mut found = false;
        let mut partition_id = PartitionId::new(0);
        for slot in self.agents.iter_mut() {
            if let Some(ref agent) = slot {
                if agent.id == id && agent.state != AgentState::Terminated {
                    if agent.state == AgentState::Terminated {
                        return Err(RvmError::InvalidPartitionState);
                    }
                    partition_id = agent.partition_id;
                    *slot = None; // Free the slot for reuse.
                    self.count = self.count.saturating_sub(1);
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(RvmError::PartitionNotFound);
        }
        emit_agent_witness(witness_log, ActionKind::TaskTerminate, partition_id, id);
        Ok(())
    }

    /// Look up an agent by identifier.
    #[must_use]
    pub fn get(&self, id: AgentId) -> Option<&Agent> {
        self.agents
            .iter()
            .filter_map(|slot| slot.as_ref())
            .find(|a| a.id == id && a.state != AgentState::Terminated)
    }

    /// Mutable lookup by identifier.
    fn get_mut(&mut self, id: AgentId) -> RvmResult<&mut Agent> {
        for slot in self.agents.iter_mut() {
            if let Some(ref mut agent) = slot {
                if agent.id == id && agent.state != AgentState::Terminated {
                    return Ok(agent);
                }
            }
        }
        Err(RvmError::PartitionNotFound)
    }
}

/// Emit a witness record for an agent lifecycle event.
fn emit_agent_witness<const W: usize>(
    log: &WitnessLog<W>,
    action: ActionKind,
    partition: PartitionId,
    agent: AgentId,
) {
    let mut record = WitnessRecord::zeroed();
    record.action_kind = action as u8;
    record.actor_partition_id = partition.as_u32();
    record.target_object_id = agent.as_u32() as u64;
    record.proof_tier = 1;
    log.append(record);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(badge: u32) -> AgentConfig {
        AgentConfig {
            badge,
            partition_id: PartitionId::new(1),
            max_memory_pages: 16,
        }
    }

    #[test]
    fn test_spawn_and_activate() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<8>::new();
        let config = make_config(42);

        let id = mgr.spawn(&config, &log).unwrap();
        assert_eq!(id, AgentId::from_badge(42));
        assert_eq!(mgr.count(), 1);

        let agent = mgr.get(id).unwrap();
        assert_eq!(agent.state, AgentState::Initializing);

        mgr.activate(id).unwrap();
        let agent = mgr.get(id).unwrap();
        assert_eq!(agent.state, AgentState::Running);
    }

    #[test]
    fn test_suspend_resume() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<8>::new();
        let id = mgr.spawn(&make_config(1), &log).unwrap();
        mgr.activate(id).unwrap();

        mgr.suspend(id, &log).unwrap();
        assert_eq!(mgr.get(id).unwrap().state, AgentState::Suspended);

        mgr.resume(id, &log).unwrap();
        assert_eq!(mgr.get(id).unwrap().state, AgentState::Running);
    }

    #[test]
    fn test_terminate() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<8>::new();
        let id = mgr.spawn(&make_config(1), &log).unwrap();
        mgr.activate(id).unwrap();

        mgr.terminate(id, &log).unwrap();
        assert_eq!(mgr.count(), 0);
        assert!(mgr.get(id).is_none());
    }

    #[test]
    fn test_capacity_limit() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<2>::new();
        mgr.spawn(&make_config(1), &log).unwrap();
        mgr.spawn(&make_config(2), &log).unwrap();
        assert_eq!(mgr.spawn(&make_config(3), &log), Err(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn test_invalid_transitions() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<8>::new();
        let id = mgr.spawn(&make_config(1), &log).unwrap();

        // Cannot suspend before activation.
        assert_eq!(mgr.suspend(id, &log), Err(RvmError::InvalidPartitionState));

        // Cannot resume from Initializing.
        assert_eq!(mgr.resume(id, &log), Err(RvmError::InvalidPartitionState));
    }

    #[test]
    fn test_witness_emitted_on_spawn() {
        let log = WitnessLog::<16>::new();
        let mut mgr = AgentManager::<8>::new();
        mgr.spawn(&make_config(1), &log).unwrap();
        assert_eq!(log.total_emitted(), 1);

        let record = log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::TaskSpawn as u8);
    }
}
