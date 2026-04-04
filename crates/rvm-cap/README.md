# rvm-cap

Capability-based access control with derivation trees and tiered proof verification.

Implements the three-layer proof system from ADR-135. Capabilities are unforgeable
kernel-managed tokens with a rights bitmap. Derivation trees enforce monotonic
attenuation: a partition can only grant capabilities it holds, and granted rights
must be equal or fewer. Delegation depth is bounded at 8 levels.

## Key Types and Traits

- `CapabilityManager` -- central manager: issue, derive, revoke, verify
- `CapabilityTable` -- per-partition capability slot table (default 256 slots)
- `DerivationTree`, `DerivationNode` -- parent-child derivation tracking
- `GrantPolicy` -- grant policy with `GRANT_ONCE` non-transitive delegation
- `RevokeResult` -- revocation result with cascade propagation info
- `ProofVerifier` -- P1 (capability check) and P2 (policy validation) verifier
- `CapSlot` -- individual slot in a capability table
- `CapError`, `ProofError` -- error types for capability operations
- `ManagerStats` -- runtime statistics for the capability manager

## Example

```rust
use rvm_cap::{CapabilityManager, CapManagerConfig, CapRights, CapType};

let config = CapManagerConfig::default();
let mut mgr = CapabilityManager::new(config);
// Issue, derive, revoke, and verify capabilities through the manager.
```

## Design Constraints

- **DC-3**: Capabilities are unforgeable, monotonically attenuated
- **DC-8**: Capabilities follow objects during partition split (type only)
- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-135: P1 < 1 us, P2 < 100 us, P3 deferred

## Workspace Dependencies

- `rvm-types`
- `spin` (spinlock for `no_std` mutual exclusion)
