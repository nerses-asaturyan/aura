use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::types::ElectionId;

// Domain separation labels for each proof type.
// These MUST be unique across the entire protocol.
pub const DOMAIN_REP_PROOF: &[u8] = b"aura/rep-proof/v1";
pub const DOMAIN_ENC_VAL_PROOF: &[u8] = b"aura/enc-val-proof/v1";
pub const DOMAIN_SER_VAL_PROOF: &[u8] = b"aura/ser-val-proof/v1";
pub const DOMAIN_DLEQ_PROOF: &[u8] = b"aura/dleq-proof/v1";
pub const DOMAIN_BIT_VECTOR_PROOF: &[u8] = b"aura/bit-vector-proof/v1";
pub const DOMAIN_SET_PROOF: &[u8] = b"aura/set-membership-proof/v1";
pub const DOMAIN_SIGNATURE: &[u8] = b"aura/signature/v1";

/// Extension trait for Merlin transcripts used throughout the Aura protocol.
///
/// All Fiat-Shamir challenges flow through this trait, ensuring consistent
/// domain separation and encoding across all proof types.
pub trait TranscriptProtocol {
    /// Append a domain separator for a specific proof type.
    fn domain_sep(&mut self, label: &[u8]);

    /// Append a labeled compressed point.
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);

    /// Append a labeled scalar.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a labeled u64.
    fn append_u64(&mut self, label: &'static [u8], value: u64);

    /// Append a labeled byte slice.
    fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Append the election ID for context binding.
    fn append_election_id(&mut self, id: &ElectionId);

    /// Extract a scalar challenge via wide reduction (64-byte challenge → Scalar).
    /// Uses `Scalar::from_bytes_mod_order_wide` for uniform distribution.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, label: &[u8]) {
        self.append_message(b"dom-sep", label);
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_u64(&mut self, label: &'static [u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.append_message(label, bytes);
    }

    fn append_election_id(&mut self, id: &ElectionId) {
        self.append_message(b"election-id", &id.0);
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

/// Create a new transcript with the standard Aura protocol label.
pub fn new_transcript(label: &'static [u8]) -> Transcript {
    Transcript::new(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_determinism() {
        let mut t1 = new_transcript(b"test");
        let mut t2 = new_transcript(b"test");

        let point = CompressedRistretto::default();
        t1.append_point(b"P", &point);
        t2.append_point(b"P", &point);

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_domains_different_challenges() {
        let point = CompressedRistretto::default();

        let mut t1 = new_transcript(b"test");
        t1.domain_sep(b"domain-a");
        t1.append_point(b"P", &point);
        let c1 = t1.challenge_scalar(b"c");

        let mut t2 = new_transcript(b"test");
        t2.domain_sep(b"domain-b");
        t2.append_point(b"P", &point);
        let c2 = t2.challenge_scalar(b"c");

        assert_ne!(c1, c2);
    }
}
