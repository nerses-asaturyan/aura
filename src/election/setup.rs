//! Voter and tallier setup, and setup verification.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::dkg::protocol::{self, DkgRound1Output};
use crate::elgamal::keys::{ElectionPublicKey, PublicKeyShare};
use crate::errors::AuraResult;
use crate::proofs::representation::{
    RepresentationProof, RepresentationStatement, RepresentationWitness,
};
use crate::types::{PedersenCommitment, VoterIndex};

use super::params::ElectionParams;

/// Voter's private state (zeroized on drop).
pub struct VoterSecret {
    /// Serial key `s_i`.
    pub serial_key: Scalar,
    /// Blinding factor `r_i`.
    pub blinding: Scalar,
}

impl Drop for VoterSecret {
    fn drop(&mut self) {
        self.serial_key.zeroize();
        self.blinding.zeroize();
    }
}

/// Voter registration output posted to the bulletin board.
#[derive(Debug, Clone)]
pub struct VoterRegistration {
    /// Voter index.
    pub index: VoterIndex,
    /// Ballot key `C_i = s_i * G + r_i * H`.
    pub ballot_key: PedersenCommitment,
    /// Proof of knowledge of `(s_i, r_i)`.
    pub proof: RepresentationProof,
}

/// Register a voter: generate ballot key and proof.
pub fn setup_voter(
    index: VoterIndex,
    params: &ElectionParams,
    rng: &mut impl CryptoRngCore,
) -> AuraResult<(VoterSecret, VoterRegistration)> {
    let g = params.generators.g;
    let h = params.generators.h;

    let serial_key = Scalar::random(rng);
    let blinding = Scalar::random(rng);
    let ballot_key = PedersenCommitment::commit(&serial_key, &blinding, &g, &h);

    let statement = RepresentationStatement {
        generators: vec![g, h],
        target: *ballot_key.point(),
    };
    let witness = RepresentationWitness {
        scalars: vec![serial_key, blinding],
    };

    let mut transcript = Transcript::new(b"aura-voter-setup");
    let proof = RepresentationProof::prove(&statement, &witness, &mut transcript, rng)?;

    let secret = VoterSecret {
        serial_key,
        blinding,
    };
    let registration = VoterRegistration {
        index,
        ballot_key,
        proof,
    };

    Ok((secret, registration))
}

/// Verify the complete election setup.
///
/// Checks all tallier key shares and voter registrations, returns the election public key.
pub fn verify_setup(
    params: &ElectionParams,
    tallier_shares: &[PublicKeyShare],
    round1_outputs: &[DkgRound1Output],
    voter_registrations: &[VoterRegistration],
) -> AuraResult<ElectionPublicKey> {
    let g = params.generators.g;
    let h = params.generators.h;

    // Verify tallier key generation
    let election_key = protocol::verify_key_gen(tallier_shares, round1_outputs, &g)?;

    // Verify voter registrations
    for reg in voter_registrations {
        let statement = RepresentationStatement {
            generators: vec![g, h],
            target: *reg.ballot_key.point(),
        };
        let mut transcript = Transcript::new(b"aura-voter-setup");
        reg.proof.verify(&statement, &mut transcript)?;
    }

    Ok(election_key)
}
