#![allow(clippy::needless_range_loop)]

pub mod errors;
pub mod types;
pub mod transcript;
pub mod generators;
pub mod proofs;
pub mod elgamal;
pub mod dkg;
pub mod signature;
pub mod election;

// Re-export primary types at crate root.
pub use errors::{AuraError, AuraResult};
pub use types::{
    Ciphertext, ChoiceIndex, CompressedPoint, ElectionId, PedersenCommitment, Point, TallierIndex,
    VoterIndex,
};
pub use generators::ElectionGenerators;
pub use transcript::TranscriptProtocol;

// Re-export merlin for transcript interop.
pub use merlin::Transcript;
