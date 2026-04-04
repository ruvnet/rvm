//! Host function interface for WASM guests.
//!
//! WASM modules running inside RVM partitions interact with the hypervisor
//! through a fixed set of host functions. Each call is capability-checked
//! before dispatch.

use rvm_types::{CapRights, CapToken, RvmError, RvmResult};

use crate::agent::AgentId;

/// The set of host functions available to WASM guests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HostFunction {
    /// Send a message to another agent or partition.
    Send = 0,
    /// Receive a pending message.
    Receive = 1,
    /// Allocate linear memory pages.
    Alloc = 2,
    /// Free previously allocated memory pages.
    Free = 3,
    /// Spawn a child agent within the same partition.
    Spawn = 4,
    /// Yield the current execution quantum.
    Yield = 5,
    /// Read the monotonic timer (nanoseconds).
    GetTime = 6,
    /// Return the caller's agent identifier.
    GetId = 7,
}

impl HostFunction {
    /// Return the minimum capability rights required for this host function.
    #[must_use]
    pub const fn required_rights(self) -> CapRights {
        match self {
            Self::Send => CapRights::WRITE,
            Self::Receive => CapRights::READ,
            Self::Alloc => CapRights::WRITE,
            Self::Free => CapRights::WRITE,
            Self::Spawn => CapRights::EXECUTE,
            Self::Yield => CapRights::READ,
            Self::GetTime => CapRights::READ,
            Self::GetId => CapRights::READ,
        }
    }
}

/// Result of a host function call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCallResult {
    /// The call succeeded with a return value.
    Success(u64),
    /// The call failed with an error code.
    Error(RvmError),
}

impl HostCallResult {
    /// Return the value if successful, or the error.
    pub fn into_result(self) -> RvmResult<u64> {
        match self {
            Self::Success(val) => Ok(val),
            Self::Error(err) => Err(err),
        }
    }

    /// Check whether the call succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
}

/// Arguments passed to a host function call.
#[derive(Debug, Clone, Copy)]
pub struct HostCallArgs {
    /// First argument (interpretation depends on function).
    pub arg0: u64,
    /// Second argument.
    pub arg1: u64,
    /// Third argument.
    pub arg2: u64,
}

impl HostCallArgs {
    /// Create args with all zeros.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            arg0: 0,
            arg1: 0,
            arg2: 0,
        }
    }
}

/// Dispatch a host function call from a WASM agent.
///
/// Performs capability checking before dispatching to the handler.
/// Returns an error if the agent lacks the required rights.
pub fn dispatch_host_call(
    agent_id: AgentId,
    function: HostFunction,
    args: &HostCallArgs,
    token: &CapToken,
) -> HostCallResult {
    // Capability check: verify the caller holds the required rights.
    let required = function.required_rights();
    if !token.has_rights(required) {
        return HostCallResult::Error(RvmError::InsufficientCapability);
    }

    // Dispatch to the appropriate stub handler.
    match function {
        HostFunction::GetId => HostCallResult::Success(agent_id.as_u32() as u64),
        HostFunction::GetTime => {
            // Stub: return arg0 as a mock timestamp.
            HostCallResult::Success(args.arg0)
        }
        HostFunction::Yield => HostCallResult::Success(0),
        HostFunction::Alloc => {
            let pages = args.arg0;
            if pages == 0 || pages > 65536 {
                HostCallResult::Error(RvmError::ResourceLimitExceeded)
            } else {
                // Stub: return the page count as acknowledgement.
                HostCallResult::Success(pages)
            }
        }
        HostFunction::Free => {
            // Stub: always succeed.
            HostCallResult::Success(0)
        }
        HostFunction::Send => {
            // Stub: return bytes sent (arg1 = length).
            HostCallResult::Success(args.arg1)
        }
        HostFunction::Receive => {
            // Stub: no messages pending.
            HostCallResult::Success(0)
        }
        HostFunction::Spawn => {
            // Stub: return the badge of the spawned agent.
            HostCallResult::Success(args.arg0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_types::{CapType, CapToken};

    fn make_token(rights: CapRights) -> CapToken {
        CapToken::new(1, CapType::Partition, rights, 0)
    }

    fn all_rights() -> CapRights {
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::EXECUTE)
    }

    #[test]
    fn test_get_id() {
        let agent = AgentId::from_badge(42);
        let token = make_token(all_rights());
        let result = dispatch_host_call(agent, HostFunction::GetId, &HostCallArgs::empty(), &token);
        assert_eq!(result, HostCallResult::Success(42));
    }

    #[test]
    fn test_capability_check_fails() {
        let agent = AgentId::from_badge(1);
        let token = make_token(CapRights::READ); // No WRITE
        let result = dispatch_host_call(
            agent,
            HostFunction::Send,
            &HostCallArgs::empty(),
            &token,
        );
        assert_eq!(result, HostCallResult::Error(RvmError::InsufficientCapability));
    }

    #[test]
    fn test_alloc_zero_pages() {
        let agent = AgentId::from_badge(1);
        let token = make_token(all_rights());
        let args = HostCallArgs { arg0: 0, arg1: 0, arg2: 0 };
        let result = dispatch_host_call(agent, HostFunction::Alloc, &args, &token);
        assert_eq!(result, HostCallResult::Error(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn test_alloc_success() {
        let agent = AgentId::from_badge(1);
        let token = make_token(all_rights());
        let args = HostCallArgs { arg0: 4, arg1: 0, arg2: 0 };
        let result = dispatch_host_call(agent, HostFunction::Alloc, &args, &token);
        assert_eq!(result, HostCallResult::Success(4));
    }

    #[test]
    fn test_yield_readonly() {
        let agent = AgentId::from_badge(1);
        let token = make_token(CapRights::READ);
        let result = dispatch_host_call(agent, HostFunction::Yield, &HostCallArgs::empty(), &token);
        assert!(result.is_success());
    }

    #[test]
    fn test_host_call_result_into_result() {
        assert_eq!(HostCallResult::Success(42).into_result(), Ok(42));
        assert_eq!(
            HostCallResult::Error(RvmError::InternalError).into_result(),
            Err(RvmError::InternalError)
        );
    }
}
