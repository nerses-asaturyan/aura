use snafu::Snafu;

/// Top-level error type for the Aura protocol.
#[derive(Debug, Snafu)]
pub enum AuraError {
    #[snafu(display("Invalid parameter: {reason}"))]
    InvalidParameter { reason: String },

    #[snafu(display("DKG protocol error: {reason}"))]
    DkgError { reason: String },

    #[snafu(display("Proof verification failed: {proof_type}"))]
    VerificationFailed { proof_type: &'static str },

    #[snafu(display("Batch verification failed for {count} proof(s)"))]
    BatchVerificationFailed { count: usize },

    #[snafu(display("Deserialization failed: {reason}"))]
    DeserializationFailed { reason: String },

    #[snafu(display("Decryption failed: no valid message found"))]
    DecryptionFailed,

    #[snafu(display("Duplicate serial number detected"))]
    DuplicateSerial,

    #[snafu(display("Invalid signature"))]
    InvalidSignature,

    #[snafu(display("Threshold not met: need {required}, have {available}"))]
    ThresholdNotMet { required: u32, available: u32 },

    #[snafu(display("Duplicate ballot rejected"))]
    DuplicateBallot,
}

pub type AuraResult<T> = Result<T, AuraError>;
