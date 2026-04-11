//! Election parameters and setup.

use crate::generators::ElectionGenerators;
use crate::types::ElectionId;

/// Configuration for creating an election.
#[derive(Debug, Clone)]
pub struct ElectionConfig {
    /// Unique election identifier.
    pub election_id: ElectionId,
    /// Human-readable description.
    pub description: String,
    /// Number of candidates/choices `k`.
    pub num_choices: u32,
    /// Choice descriptions.
    pub choice_descriptions: Vec<String>,
    /// Minimum choices a voter must make.
    pub min_choices: u32,
    /// Maximum choices a voter may make.
    pub max_choices: u32,
    /// Number of voters `N_voters = n^m`.
    pub num_voters: u32,
    /// Base for commitment set proof decomposition.
    pub set_base: u32,
    /// Depth for commitment set proof decomposition.
    pub set_depth: u32,
    /// Number of talliers.
    pub num_talliers: u32,
    /// Threshold of talliers required for decryption.
    pub threshold: u32,
}

/// Public parameters for an election, available to all participants.
#[derive(Debug, Clone)]
pub struct ElectionParams {
    /// Unique election identifier.
    pub election_id: ElectionId,
    /// Human-readable description.
    pub description: String,
    /// Number of candidates/choices `k`.
    pub num_choices: u32,
    /// Choice descriptions.
    pub choice_descriptions: Vec<String>,
    /// Minimum choices.
    pub min_choices: u32,
    /// Maximum choices.
    pub max_choices: u32,
    /// Padded number of choices: `k' = k + k_max - k_min`.
    pub padded_choices: u32,
    /// Election generators (G, H, F, H_0..H_{k'-1}).
    pub generators: ElectionGenerators,
    /// Number of voters.
    pub num_voters: u32,
    /// Base `n` for set proof.
    pub set_base: u32,
    /// Depth `m` for set proof.
    pub set_depth: u32,
    /// Number of talliers.
    pub num_talliers: u32,
    /// Decryption threshold.
    pub threshold: u32,
}

/// Create election parameters from a configuration.
pub fn setup_election(config: ElectionConfig) -> ElectionParams {
    let padded_choices = config.num_choices + config.max_choices - config.min_choices;
    let generators = ElectionGenerators::new(&config.election_id, padded_choices as usize);

    ElectionParams {
        election_id: config.election_id,
        description: config.description,
        num_choices: config.num_choices,
        choice_descriptions: config.choice_descriptions,
        min_choices: config.min_choices,
        max_choices: config.max_choices,
        padded_choices,
        generators,
        num_voters: config.num_voters,
        set_base: config.set_base,
        set_depth: config.set_depth,
        num_talliers: config.num_talliers,
        threshold: config.threshold,
    }
}
