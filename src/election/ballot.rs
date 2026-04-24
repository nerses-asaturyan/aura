//! Ballot creation and verification.
//!
//! Implements the `Vote` and `VerifyBallot` algorithms from the paper.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::elgamal::encrypt::encrypt;
use crate::elgamal::keys::ElectionPublicKey;
use crate::errors::{AuraError, AuraResult};
use crate::proofs::bit_vector::{BitVectorProof, BitVectorStatement, BitVectorWitness};
use crate::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetProof, CommitmentSetStatement, CommitmentSetWitness,
};
use crate::proofs::encryption_validity::{
    EncValStatement, EncValWitness, EncryptionValidityProof,
};
use crate::proofs::serial_validity::{SerValStatement, SerValWitness, SerialValidityProof};
use crate::signature::{self, SchnorrSignature};
use crate::transcript::TranscriptProtocol;
use crate::types::{Ciphertext, PedersenCommitment};

use super::params::ElectionParams;
use super::setup::VoterSecret;

/// Compute the canonical signing message over every ballot field except the
/// signature itself.
///
/// Absorbs ciphertexts, every proof component, the serial offset, and the
/// encrypted serial into a Merlin transcript and extracts a 64-byte challenge.
/// Signing this digest binds the Schnorr signature to the whole ballot: any
/// mutation of any field produces a different digest and invalidates the
/// signature.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ballot_signing_message_for_fields(
    encrypted_choices: &[(Ciphertext, EncryptionValidityProof)],
    bit_proof: &BitVectorProof,
    serial_offset: &PedersenCommitment,
    encrypted_serial: &Ciphertext,
    set_proof: &CommitmentSetProof,
    serial_proof: &SerialValidityProof,
) -> [u8; 64] {
    let mut t = Transcript::new(b"aura/ballot-digest/v1");

    t.append_u64(b"n_choices", encrypted_choices.len() as u64);
    for (ct, proof) in encrypted_choices {
        t.append_point(b"ct.d", &ct.d.compress());
        t.append_point(b"ct.e", &ct.e.compress());
        t.append_point(b"enc.cd", &proof.commitment_d);
        t.append_point(b"enc.ce", &proof.commitment_e);
        t.append_scalar(b"enc.sr", &proof.response_r);
        t.append_scalar(b"enc.sm", &proof.response_m);
    }

    t.append_point(b"bit.a", &bit_proof.a);
    t.append_point(b"bit.c", &bit_proof.c);
    t.append_point(b"bit.d", &bit_proof.d);
    t.append_u64(b"bit.f_len", bit_proof.f.len() as u64);
    for fi in &bit_proof.f {
        t.append_scalar(b"bit.f", fi);
    }
    t.append_scalar(b"bit.za", &bit_proof.z_a);
    t.append_scalar(b"bit.zc", &bit_proof.z_c);

    t.append_point(b"offset", &serial_offset.point().compress());
    t.append_point(b"serial.d", &encrypted_serial.d.compress());
    t.append_point(b"serial.e", &encrypted_serial.e.compress());

    t.append_u64(b"set.cl_outer", set_proof.cl.len() as u64);
    for row in &set_proof.cl {
        t.append_u64(b"set.cl_inner", row.len() as u64);
        for p in row {
            t.append_point(b"set.cl", p);
        }
    }
    t.append_u64(b"set.ct_len", set_proof.cross_terms.len() as u64);
    for p in &set_proof.cross_terms {
        t.append_point(b"set.ct", p);
    }
    t.append_u64(b"set.f_outer", set_proof.f_matrix.len() as u64);
    for row in &set_proof.f_matrix {
        t.append_u64(b"set.f_inner", row.len() as u64);
        for s in row {
            t.append_scalar(b"set.f", s);
        }
    }
    t.append_scalar(b"set.z", &set_proof.z);

    t.append_point(b"ser.cc", &serial_proof.commitment_c);
    t.append_point(b"ser.cd", &serial_proof.commitment_d);
    t.append_point(b"ser.ce", &serial_proof.commitment_e);
    t.append_scalar(b"ser.ss", &serial_proof.response_s);
    t.append_scalar(b"ser.srp", &serial_proof.response_r_prime);
    t.append_scalar(b"ser.srpp", &serial_proof.response_r_double_prime);

    let mut out = [0u8; 64];
    t.challenge_bytes(b"digest", &mut out);
    out
}

/// Convenience wrapper that computes the signing digest from a fully-assembled
/// `Ballot` (ignoring its `signature` field).
pub(crate) fn ballot_signing_message(ballot: &Ballot) -> [u8; 64] {
    ballot_signing_message_for_fields(
        &ballot.encrypted_choices,
        &ballot.bit_proof,
        &ballot.serial_offset,
        &ballot.encrypted_serial,
        &ballot.set_proof,
        &ballot.serial_proof,
    )
}

/// A complete ballot posted to the bulletin board.
#[derive(Debug, Clone)]
pub struct Ballot {
    /// Encrypted choices: ciphertext + encryption validity proof for each of k' choices.
    pub encrypted_choices: Vec<(Ciphertext, EncryptionValidityProof)>,
    /// Bit vector proof that choices are binary and sum to k_max.
    pub bit_proof: BitVectorProof,
    /// Serial offset commitment `C'_i = s_i * G + r'_i * H`.
    pub serial_offset: PedersenCommitment,
    /// Encrypted serial number `(D'_i, E'_i)`.
    pub encrypted_serial: Ciphertext,
    /// Set membership proof (voter is in the voter list).
    pub set_proof: CommitmentSetProof,
    /// Serial validity proof binding ballot to voter.
    pub serial_proof: SerialValidityProof,
    /// Signature on the ballot.
    pub signature: SchnorrSignature,
}

/// Cast a vote: create a complete ballot.
///
/// - `voter_secret`: the voter's private key material (s_i, r_i)
/// - `voter_index`: the voter's index in the voter list (0-indexed)
/// - `choices`: boolean vector of length `k` representing the voter's choices
/// - `params`: election parameters
/// - `election_key`: the election public key Y
/// - `all_ballot_keys`: all voter ballot key commitments from registration
pub fn vote(
    voter_secret: &VoterSecret,
    voter_index: u32,
    choices: &[bool],
    params: &ElectionParams,
    election_key: &ElectionPublicKey,
    all_ballot_keys: &[PedersenCommitment],
    rng: &mut impl CryptoRngCore,
) -> AuraResult<Ballot> {
    let k = params.num_choices as usize;
    let k_prime = params.padded_choices as usize;
    let k_min = params.min_choices;
    let k_max = params.max_choices;

    if choices.len() != k {
        return Err(AuraError::InvalidParameter {
            reason: format!("expected {} choices, got {}", k, choices.len()),
        });
    }

    let num_selected: u32 = choices.iter().filter(|&&c| c).count() as u32;
    if num_selected < k_min || num_selected > k_max {
        return Err(AuraError::InvalidParameter {
            reason: format!(
                "selected {} choices, must be between {} and {}",
                num_selected, k_min, k_max
            ),
        });
    }

    let g = params.generators.g;
    let h = params.generators.h;
    let f = params.generators.f;

    // Step 1-3: Construct choice vector with padding, encrypt each choice.
    let mut choice_bits: Vec<Scalar> = Vec::with_capacity(k_prime);
    for &c in choices {
        choice_bits.push(if c { Scalar::ONE } else { Scalar::ZERO });
    }

    // Padding: fill to k_max total ones.
    let padding_ones = k_max - num_selected;
    for j in k..k_prime {
        if (j - k) < padding_ones as usize {
            choice_bits.push(Scalar::ONE);
        } else {
            choice_bits.push(Scalar::ZERO);
        }
    }

    // Encrypt each choice and create validity proofs.
    let mut encrypted_choices = Vec::with_capacity(k_prime);
    let mut nonces = Vec::with_capacity(k_prime);
    let mut ciphertexts = Vec::with_capacity(k_prime);

    for j in 0..k_prime {
        let (ct, r) = encrypt(
            &choice_bits[j],
            &params.generators.h_msg[j],
            &g,
            election_key,
            rng,
        );

        let enc_statement = EncValStatement {
            g,
            y: *election_key.point(),
            h_i: params.generators.h_msg[j],
            d: ct.d,
            e: ct.e,
        };
        let enc_witness = EncValWitness {
            r,
            m: choice_bits[j],
        };

        let mut enc_transcript = Transcript::new(b"aura-enc-val");
        let enc_proof =
            EncryptionValidityProof::prove(&enc_statement, &enc_witness, &mut enc_transcript, rng)?;

        encrypted_choices.push((ct, enc_proof));
        nonces.push(r);
        ciphertexts.push(ct);
    }

    // Step 4: Bit vector commitment proof.
    // The commitment B = sum(E_{i,j}) = (sum of nonces)*Y + sum(choice_bits[j] * H_j)
    // Blinding generator is Y, component generators are H_j.
    let e_sum: RistrettoPoint = ciphertexts.iter().map(|ct| ct.e).sum();
    let nonce_sum: Scalar = nonces.iter().sum();

    let bit_statement = BitVectorStatement {
        generators: params.generators.h_msg.clone(),
        h: *election_key.point(), // Y is the blinding generator for the E components
        b: e_sum,
        w: k_max,
    };
    let bit_witness = BitVectorWitness {
        bits: choice_bits,
        blinding: nonce_sum,
    };

    let mut bit_transcript = Transcript::new(b"aura-bit-vector");
    let bit_proof = BitVectorProof::prove(&bit_statement, &bit_witness, &mut bit_transcript, rng)?;

    // Step 5: Serial offset commitment C'_i = s_i * G + r'_i * H.
    let r_prime = Scalar::random(rng);
    let serial_offset = PedersenCommitment::commit(&voter_secret.serial_key, &r_prime, &g, &h);

    // Step 6: Encrypt serial number.
    let r_double_prime = Scalar::random(rng);
    let encrypted_serial = Ciphertext {
        d: r_double_prime * g,
        e: voter_secret.serial_key * f + r_double_prime * election_key.point(),
    };

    // Step 7: Commitment set membership proof.
    let all_commitment_points: Vec<RistrettoPoint> =
        all_ballot_keys.iter().map(|c| *c.point()).collect();

    let set_params = CommitmentSetParams {
        n: params.set_base,
        m: params.set_depth,
        g,
        h,
    };
    let set_statement = CommitmentSetStatement {
        params: set_params,
        commitments: all_commitment_points,
        c_prime: *serial_offset.point(),
    };
    let set_witness = CommitmentSetWitness {
        index: voter_index,
        blinding: voter_secret.blinding - r_prime, // r_i - r'_i
    };

    let mut set_transcript = Transcript::new(b"aura-set-membership");
    let set_proof =
        CommitmentSetProof::prove(&set_statement, &set_witness, &mut set_transcript, rng)?;

    // Step 9: Serial validity proof.
    let ser_statement = SerValStatement {
        f,
        g,
        h,
        y: *election_key.point(),
        c_prime: *serial_offset.point(),
        d_prime: encrypted_serial.d,
        e_prime: encrypted_serial.e,
    };
    let ser_witness = SerValWitness {
        s: voter_secret.serial_key,
        r_prime,
        r_double_prime,
    };

    let mut ser_transcript = Transcript::new(b"aura-serial-validity");
    let serial_proof =
        SerialValidityProof::prove(&ser_statement, &ser_witness, &mut ser_transcript, rng)?;

    // Step 10: Sign a digest of the complete ballot with the serial key
    // (against generator F). The digest covers every ballot field except the
    // signature itself, so any mutation invalidates the signature.
    let ballot_message = ballot_signing_message_for_fields(
        &encrypted_choices,
        &bit_proof,
        &serial_offset,
        &encrypted_serial,
        &set_proof,
        &serial_proof,
    );
    let sig = signature::sign(
        &voter_secret.serial_key,
        &f,
        &ballot_message,
        &params.election_id,
        rng,
    );

    Ok(Ballot {
        encrypted_choices,
        bit_proof,
        serial_offset,
        encrypted_serial,
        set_proof,
        serial_proof,
        signature: sig,
    })
}

/// Verify a ballot.
pub fn verify_ballot(
    ballot: &Ballot,
    params: &ElectionParams,
    election_key: &ElectionPublicKey,
    all_ballot_keys: &[PedersenCommitment],
) -> AuraResult<()> {
    let k_prime = params.padded_choices as usize;
    let g = params.generators.g;
    let h = params.generators.h;
    let f = params.generators.f;

    if ballot.encrypted_choices.len() != k_prime {
        return Err(AuraError::VerificationFailed {
            proof_type: "ballot_structure",
        });
    }

    // Verify each encryption validity proof.
    for (j, (ct, proof)) in ballot.encrypted_choices.iter().enumerate() {
        let statement = EncValStatement {
            g,
            y: *election_key.point(),
            h_i: params.generators.h_msg[j],
            d: ct.d,
            e: ct.e,
        };
        let mut transcript = Transcript::new(b"aura-enc-val");
        proof.verify(&statement, &mut transcript)?;
    }

    // Verify bit vector proof.
    let e_sum: RistrettoPoint = ballot
        .encrypted_choices
        .iter()
        .map(|(ct, _)| ct.e)
        .sum();

    let bit_statement = BitVectorStatement {
        generators: params.generators.h_msg.clone(),
        h: *election_key.point(),
        b: e_sum,
        w: params.max_choices,
    };

    let mut bit_transcript = Transcript::new(b"aura-bit-vector");
    ballot.bit_proof.verify(&bit_statement, &mut bit_transcript)?;

    // Verify set membership proof.
    let all_commitment_points: Vec<RistrettoPoint> =
        all_ballot_keys.iter().map(|c| *c.point()).collect();

    let set_params = CommitmentSetParams {
        n: params.set_base,
        m: params.set_depth,
        g,
        h,
    };
    let set_statement = CommitmentSetStatement {
        params: set_params,
        commitments: all_commitment_points,
        c_prime: *ballot.serial_offset.point(),
    };

    let mut set_transcript = Transcript::new(b"aura-set-membership");
    ballot
        .set_proof
        .verify(&set_statement, &mut set_transcript)?;

    // Verify serial validity proof.
    let ser_statement = SerValStatement {
        f,
        g,
        h,
        y: *election_key.point(),
        c_prime: *ballot.serial_offset.point(),
        d_prime: ballot.encrypted_serial.d,
        e_prime: ballot.encrypted_serial.e,
    };

    let mut ser_transcript = Transcript::new(b"aura-serial-validity");
    ballot
        .serial_proof
        .verify(&ser_statement, &mut ser_transcript)?;

    // Note: Signature is verified during tally (after serial number decryption
    // reveals the public key).

    Ok(())
}
