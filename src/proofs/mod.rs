// Hand-rolled implementations (paper-faithful baseline).
pub mod representation;
pub mod dleq;
pub mod encryption_validity;
pub mod serial_validity;
pub mod bit_vector;
pub mod commitment_set;

// Library-backed implementations (enabled via `lib-proofs` feature).
//
// These mirror the API of the hand-rolled modules above, with the same
// `Statement` / `Witness` / `Proof` struct names and prove/verify signatures.
// Each proof delegates internally to a different ZK library on its native
// crypto stack; bridging happens at the module boundary via canonical 32-byte
// Ristretto255 / Scalar encodings (see `lib_backed::bridge`).
#[cfg(feature = "lib-proofs")]
pub mod lib_backed;
