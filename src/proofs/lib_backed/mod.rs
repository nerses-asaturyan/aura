//! Library-backed proof implementations (`lib-proofs` feature).
//!
//! Each submodule mirrors the API of the hand-rolled proof in the parent
//! `proofs::` module so call sites are unchanged when the feature flag flips.
//! Internally, each submodule delegates to a different ZK library on its
//! native crypto stack:
//!
//! | proof | library | curve crate / merlin |
//! | ----- | ------- | -------------------- |
//! | representation       | `zkp` 0.8                | `curve25519-dalek-ng 3` / `merlin 2` |
//! | dleq                 | `sigma-protocols` 0.5    | `curve25519-dalek 4.1` (no merlin)   |
//! | encryption_validity  | `zkp` 0.8                | `curve25519-dalek-ng 3` / `merlin 2` |
//! | serial_validity      | `zkp` 0.8                | `curve25519-dalek-ng 3` / `merlin 2` |
//! | bit_vector           | `bulletproofs` 5 R1CS    | `curve25519-dalek 4.1` / `merlin 3`  |
//! | commitment_set       | `one-of-many-proofs`     | `curve25519-dalek 2` / `merlin 2`    |
//!
//! Bridging happens at the module boundary via the canonical 32-byte Ristretto255
//! encoding (RFC 9496) and the canonical 32-byte little-endian Scalar encoding —
//! both are stable across all dalek versions.

pub mod bridge;

pub mod representation;
pub mod dleq;
pub mod encryption_validity;
pub mod serial_validity;
pub mod bit_vector;
pub mod commitment_set;
