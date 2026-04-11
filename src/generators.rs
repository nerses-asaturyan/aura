use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

use crate::types::ElectionId;

/// The full set of generators for an election.
///
/// All generators are derived deterministically from the election ID,
/// ensuring "nothing up my sleeve" parameters.
#[derive(Debug, Clone)]
pub struct ElectionGenerators {
    /// Base generator `G` (used for commitments and public keys).
    pub g: RistrettoPoint,
    /// Pedersen blinding generator `H`.
    pub h: RistrettoPoint,
    /// Serial number generator `F`.
    pub f: RistrettoPoint,
    /// Message generators `H_0, ..., H_{k'-1}` for ElGamal encryption.
    pub h_msg: Vec<RistrettoPoint>,
}

impl ElectionGenerators {
    /// Create election generators by deriving them from the election ID.
    ///
    /// `k_prime` is the padded number of choices: `k + k_max - k_min`.
    pub fn new(election_id: &ElectionId, k_prime: usize) -> Self {
        let g = derive_generator(election_id, b"G", 0);
        let h = derive_generator(election_id, b"H", 0);
        let f = derive_generator(election_id, b"F", 0);

        let h_msg: Vec<RistrettoPoint> = (0..k_prime)
            .map(|i| derive_generator(election_id, b"H_msg", i as u64))
            .collect();

        Self { g, h, f, h_msg }
    }
}

/// Derive a single generator by hashing to the Ristretto group.
///
/// Uses `RistrettoPoint::hash_from_bytes::<Sha512>` which maps uniformly
/// to the group via Elligator, producing a point with unknown discrete log
/// relative to any other generator derived with different inputs.
fn derive_generator(
    election_id: &ElectionId,
    label: &[u8],
    index: u64,
) -> RistrettoPoint {
    // Build a domain-separated seed: "aura/gen/{election_id}/{label}/{index}"
    let mut seed = Vec::new();
    seed.extend_from_slice(b"aura/gen/");
    seed.extend_from_slice(&(election_id.0.len() as u64).to_le_bytes());
    seed.extend_from_slice(&election_id.0);
    seed.push(b'/');
    seed.extend_from_slice(label);
    seed.push(b'/');
    seed.extend_from_slice(&index.to_le_bytes());

    // Hash the seed to 64 bytes, then map to a Ristretto point.
    // This is equivalent to the old hash_from_bytes::<Sha512> from dalek 3.x.
    let hash = Sha512::digest(&seed);
    let hash_bytes: [u8; 64] = hash.into();
    RistrettoPoint::from_uniform_bytes(&hash_bytes)
}

/// Derive `count` generators with the given label, for use outside elections.
pub fn derive_generators(
    election_id: &ElectionId,
    label: &[u8],
    count: usize,
) -> Vec<RistrettoPoint> {
    (0..count)
        .map(|i| derive_generator(election_id, label, i as u64))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic() {
        let id = ElectionId(b"test-election-2026".to_vec());
        let gen1 = ElectionGenerators::new(&id, 4);
        let gen2 = ElectionGenerators::new(&id, 4);

        assert_eq!(gen1.g, gen2.g);
        assert_eq!(gen1.h, gen2.h);
        assert_eq!(gen1.f, gen2.f);
        assert_eq!(gen1.h_msg, gen2.h_msg);
    }

    #[test]
    fn different_elections_different_generators() {
        let id1 = ElectionId(b"election-a".to_vec());
        let id2 = ElectionId(b"election-b".to_vec());
        let gen1 = ElectionGenerators::new(&id1, 4);
        let gen2 = ElectionGenerators::new(&id2, 4);

        assert_ne!(gen1.g, gen2.g);
        assert_ne!(gen1.h, gen2.h);
    }

    #[test]
    fn generators_are_independent() {
        let id = ElectionId(b"test".to_vec());
        let gen = ElectionGenerators::new(&id, 4);

        // All generators should be distinct
        assert_ne!(gen.g, gen.h);
        assert_ne!(gen.g, gen.f);
        assert_ne!(gen.h, gen.f);
        for (i, hi) in gen.h_msg.iter().enumerate() {
            assert_ne!(hi, &gen.g);
            assert_ne!(hi, &gen.h);
            for (j, hj) in gen.h_msg.iter().enumerate() {
                if i != j {
                    assert_ne!(hi, hj);
                }
            }
        }
    }

    #[test]
    fn correct_number_of_message_generators() {
        let id = ElectionId(b"test".to_vec());
        let gen = ElectionGenerators::new(&id, 10);
        assert_eq!(gen.h_msg.len(), 10);
    }
}
