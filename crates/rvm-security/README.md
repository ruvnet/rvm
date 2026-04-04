# rvm-security

Unified security gate for the RVM microhypervisor.

Provides the policy decision point that every hypercall passes through.
The gate combines three stages: capability type and rights checking, proof
commitment presence verification, and witness logging. Only after all
stages pass does the hypercall proceed. Actual proof verification is
delegated to `rvm-proof`; this crate handles the policy decision.

## Three-Stage Gate

1. **Capability check** -- does the caller hold the required type and rights?
2. **Proof verification** -- is the proof commitment present and non-zero?
3. **Witness logging** -- record the decision (caller responsibility)

## Key Types and Functions

- `GateRequest` -- bundles token, required type, required rights, optional proof commitment
- `PolicyDecision` -- `Allow` or `Deny(RvmError)`
- `evaluate(request)` -- evaluate a gate request, return `PolicyDecision`
- `enforce(request)` -- evaluate and return `RvmResult<()>` (convenience)

## Example

```rust
use rvm_security::{GateRequest, PolicyDecision, evaluate, enforce};
use rvm_types::{CapToken, CapType, CapRights};

let token = CapToken::new(1, CapType::Partition, CapRights::READ, 0);
let request = GateRequest {
    token: &token,
    required_type: CapType::Partition,
    required_rights: CapRights::READ,
    proof_commitment: None,
};

assert_eq!(evaluate(&request), PolicyDecision::Allow);
assert!(enforce(&request).is_ok());
```

## Design Constraints

- **DC-3**: Capabilities are unforgeable, monotonically attenuated
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Workspace Dependencies

- `rvm-types`
- `rvm-witness`
