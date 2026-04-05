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
    /// Submit a GPU compute kernel for execution.
    GpuLaunch = 8,
    /// Allocate GPU buffer memory.
    GpuAlloc = 9,
    /// Free GPU buffer memory.
    GpuFree = 10,
    /// Copy data between CPU and GPU buffers.
    GpuTransfer = 11,
    /// Wait for GPU operation to complete.
    GpuSync = 12,
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
            Self::GpuLaunch => CapRights::EXECUTE.union(CapRights::WRITE),
            Self::GpuAlloc => CapRights::WRITE,
            Self::GpuFree => CapRights::WRITE,
            Self::GpuTransfer => CapRights::READ.union(CapRights::WRITE),
            Self::GpuSync => CapRights::READ,
        }
    }

    /// Try to convert a raw `u8` value to a `HostFunction` variant.
    ///
    /// Returns `None` if the value does not correspond to a known host function.
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Send),
            1 => Some(Self::Receive),
            2 => Some(Self::Alloc),
            3 => Some(Self::Free),
            4 => Some(Self::Spawn),
            5 => Some(Self::Yield),
            6 => Some(Self::GetTime),
            7 => Some(Self::GetId),
            8 => Some(Self::GpuLaunch),
            9 => Some(Self::GpuAlloc),
            10 => Some(Self::GpuFree),
            11 => Some(Self::GpuTransfer),
            12 => Some(Self::GpuSync),
            _ => None,
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

/// Trait for host-side operations that WASM agents delegate to the kernel.
///
/// Implement this trait to connect host function dispatch to real kernel
/// subsystems (IPC, memory allocator, scheduler). The default implementation
/// provides the stub behaviour used in testing.
pub trait HostContext {
    /// Send `length` bytes to the target partition.
    ///
    /// `arg0` = target partition ID, `arg1` = length, `arg2` = reserved.
    /// Returns the number of bytes accepted.
    fn send(&mut self, sender: AgentId, target: u64, length: u64) -> RvmResult<u64> {
        let _ = (sender, target);
        Ok(length) // stub: accept all
    }

    /// Receive a pending message.
    ///
    /// Returns the message length, or 0 if no message is pending.
    fn receive(&mut self, receiver: AgentId) -> RvmResult<u64> {
        let _ = receiver;
        Ok(0) // stub: no messages
    }

    /// Allocate `pages` of linear memory.
    ///
    /// Returns the base address of the allocation.
    fn alloc(&mut self, agent: AgentId, pages: u64) -> RvmResult<u64> {
        let _ = agent;
        if pages == 0 || pages > 65536 {
            Err(RvmError::ResourceLimitExceeded)
        } else {
            Ok(pages) // stub: return page count as acknowledgement
        }
    }

    /// Free previously allocated memory at `base`.
    fn free(&mut self, agent: AgentId, base: u64) -> RvmResult<u64> {
        let _ = (agent, base);
        Ok(0) // stub: always succeed
    }

    /// Spawn a child agent with the given badge.
    ///
    /// Returns the new agent's ID.
    fn spawn(&mut self, parent: AgentId, badge: u64) -> RvmResult<u64> {
        let _ = parent;
        Ok(badge) // stub: return badge
    }

    /// Yield the current quantum.
    fn yield_quantum(&mut self, agent: AgentId) -> RvmResult<u64> {
        let _ = agent;
        Ok(0)
    }

    /// Read the monotonic timer in nanoseconds.
    fn get_time(&self) -> u64 {
        0 // stub: no real timer
    }

    /// Submit a GPU compute kernel for execution.
    ///
    /// `kernel_id` identifies the compiled kernel, `config` encodes grid/block dimensions.
    /// Returns a handle for the submitted operation.
    #[cfg(feature = "gpu")]
    fn gpu_launch(&mut self, agent: AgentId, kernel_id: u64, config: u64) -> RvmResult<u64> {
        let _ = (agent, kernel_id, config);
        Err(RvmError::InternalError) // stub: GPU not available
    }

    /// Allocate GPU buffer memory.
    ///
    /// Returns a buffer handle for the allocated region of `size` bytes.
    #[cfg(feature = "gpu")]
    fn gpu_alloc(&mut self, agent: AgentId, size: u64) -> RvmResult<u64> {
        let _ = (agent, size);
        Err(RvmError::InternalError) // stub: GPU not available
    }

    /// Free a previously allocated GPU buffer.
    #[cfg(feature = "gpu")]
    fn gpu_free(&mut self, agent: AgentId, buffer_id: u64) -> RvmResult<u64> {
        let _ = (agent, buffer_id);
        Err(RvmError::InternalError) // stub: GPU not available
    }

    /// Copy data between CPU and GPU buffers.
    ///
    /// `src` and `dst` are buffer handles, `size` is the byte count.
    #[cfg(feature = "gpu")]
    fn gpu_transfer(&mut self, agent: AgentId, src: u64, dst: u64, size: u64) -> RvmResult<u64> {
        let _ = (agent, src, dst, size);
        Err(RvmError::InternalError) // stub: GPU not available
    }

    /// Wait for all pending GPU operations for this agent to complete.
    #[cfg(feature = "gpu")]
    fn gpu_sync(&mut self, agent: AgentId) -> RvmResult<u64> {
        let _ = agent;
        Err(RvmError::InternalError) // stub: GPU not available
    }
}

/// Default stub host context for testing.
pub struct StubHostContext;

impl HostContext for StubHostContext {}

/// Dispatch a host function call from a WASM agent.
///
/// Performs capability checking before dispatching to the handler.
/// Returns an error if the agent lacks the required rights.
///
/// Use `StubHostContext` for testing, or implement `HostContext` on your
/// kernel struct to connect to real subsystems.
pub fn dispatch_host_call<H: HostContext>(
    agent_id: AgentId,
    function: HostFunction,
    args: &HostCallArgs,
    token: &CapToken,
    ctx: &mut H,
) -> HostCallResult {
    // Capability check: verify the caller holds the required rights.
    let required = function.required_rights();
    if !token.has_rights(required) {
        return HostCallResult::Error(RvmError::InsufficientCapability);
    }

    // Dispatch to the host context handler.
    match function {
        HostFunction::GetId => HostCallResult::Success(agent_id.as_u32() as u64),
        HostFunction::GetTime => HostCallResult::Success(ctx.get_time()),
        HostFunction::Yield => match ctx.yield_quantum(agent_id) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        HostFunction::Alloc => match ctx.alloc(agent_id, args.arg0) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        HostFunction::Free => match ctx.free(agent_id, args.arg0) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        HostFunction::Send => match ctx.send(agent_id, args.arg0, args.arg1) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        HostFunction::Receive => match ctx.receive(agent_id) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        HostFunction::Spawn => match ctx.spawn(agent_id, args.arg0) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(feature = "gpu")]
        HostFunction::GpuLaunch => match ctx.gpu_launch(agent_id, args.arg0, args.arg1) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(feature = "gpu")]
        HostFunction::GpuAlloc => match ctx.gpu_alloc(agent_id, args.arg0) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(feature = "gpu")]
        HostFunction::GpuFree => match ctx.gpu_free(agent_id, args.arg0) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(feature = "gpu")]
        HostFunction::GpuTransfer => match ctx.gpu_transfer(agent_id, args.arg0, args.arg1, args.arg2) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(feature = "gpu")]
        HostFunction::GpuSync => match ctx.gpu_sync(agent_id) {
            Ok(v) => HostCallResult::Success(v),
            Err(e) => HostCallResult::Error(e),
        },
        #[cfg(not(feature = "gpu"))]
        HostFunction::GpuLaunch | HostFunction::GpuAlloc | HostFunction::GpuFree
        | HostFunction::GpuTransfer | HostFunction::GpuSync => {
            HostCallResult::Error(RvmError::InternalError)
        }
    }
}

/// Convenience: dispatch with the default stub context.
///
/// Retained for backward compatibility with tests that don't need
/// a real host context.
pub fn dispatch_host_call_stub(
    agent_id: AgentId,
    function: HostFunction,
    args: &HostCallArgs,
    token: &CapToken,
) -> HostCallResult {
    dispatch_host_call(agent_id, function, args, token, &mut StubHostContext)
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
        let result = dispatch_host_call_stub(agent, HostFunction::GetId, &HostCallArgs::empty(), &token);
        assert_eq!(result, HostCallResult::Success(42));
    }

    #[test]
    fn test_capability_check_fails() {
        let agent = AgentId::from_badge(1);
        let token = make_token(CapRights::READ); // No WRITE
        let result = dispatch_host_call_stub(
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
        let result = dispatch_host_call_stub(agent, HostFunction::Alloc, &args, &token);
        assert_eq!(result, HostCallResult::Error(RvmError::ResourceLimitExceeded));
    }

    #[test]
    fn test_alloc_success() {
        let agent = AgentId::from_badge(1);
        let token = make_token(all_rights());
        let args = HostCallArgs { arg0: 4, arg1: 0, arg2: 0 };
        let result = dispatch_host_call_stub(agent, HostFunction::Alloc, &args, &token);
        assert_eq!(result, HostCallResult::Success(4));
    }

    #[test]
    fn test_yield_readonly() {
        let agent = AgentId::from_badge(1);
        let token = make_token(CapRights::READ);
        let result = dispatch_host_call_stub(agent, HostFunction::Yield, &HostCallArgs::empty(), &token);
        assert!(result.is_success());
    }

    #[test]
    fn test_custom_host_context() {
        struct CountingCtx { send_count: u64 }
        impl HostContext for CountingCtx {
            fn send(&mut self, _: AgentId, _: u64, length: u64) -> RvmResult<u64> {
                self.send_count += 1;
                Ok(length)
            }
        }

        let agent = AgentId::from_badge(1);
        let token = make_token(all_rights());
        let mut ctx = CountingCtx { send_count: 0 };
        let args = HostCallArgs { arg0: 2, arg1: 100, arg2: 0 };

        let result = dispatch_host_call(agent, HostFunction::Send, &args, &token, &mut ctx);
        assert_eq!(result, HostCallResult::Success(100));
        assert_eq!(ctx.send_count, 1);

        dispatch_host_call(agent, HostFunction::Send, &args, &token, &mut ctx);
        assert_eq!(ctx.send_count, 2);
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
