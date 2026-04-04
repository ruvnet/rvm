# rvm-proof

Proof-gated state transitions for the RVM microhypervisor.

Every mutation to partition state requires a valid proof recorded in the
witness trail. This crate defines the proof tiers, the `Proof` payload
structure, and verification functions. Currently ships with a stub Hash-tier
verifier; Witness-tier and ZK-tier verification are accepted but not yet
fully implemented.

## Proof Tiers

| Tier | Verification | Cost | Use Case |
|------|-------------|------|----------|
| `Hash` | Preimage check | O(1) | Routine transitions |
| `Witness` | Witness chain verification | O(n) | Cross-partition ops |
| `Zk` | Zero-knowledge proof | Expensive | Privacy-preserving |

## Key Types and Functions

- `ProofTier` -- enum: `Hash`, `Witness`, `Zk`
- `Proof` -- proof payload with tier, commitment hash, and up to 64 bytes of data
- `verify(proof, commitment)` -- verify a proof against an expected commitment
- `verify_with_cap(proof, commitment, token)` -- verify with capability gate

## Example

```rust
use rvm_proof::{Proof, ProofTier, verify};
use rvm_types::WitnessHash;

let commitment = WitnessHash::from_bytes([0xAB; 32]);
let proof = Proof::hash_proof(commitment, b"preimage-data");
assert!(verify(&proof, &commitment).is_ok());
```

## Design Constraints

- **DC-15**: `#![no_std]`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- ADR-135: three-tier proof system (P1/P2/P3)

## Workspace Dependencies

- `rvm-types`
- `rvm-cap`
- `rvm-witness`
