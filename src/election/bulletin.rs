//! Bulletin board trait and in-memory implementation.

use crate::dkg::protocol::DkgRound1Output;
use crate::elgamal::keys::PublicKeyShare;

use super::ballot::Ballot;
use super::params::ElectionParams;
use super::setup::VoterRegistration;

/// In-memory bulletin board for testing and single-process simulations.
#[derive(Debug, Clone)]
pub struct InMemoryBulletinBoard {
    pub params: Option<ElectionParams>,
    pub round1_outputs: Vec<DkgRound1Output>,
    pub tallier_shares: Vec<PublicKeyShare>,
    pub voter_registrations: Vec<VoterRegistration>,
    pub ballots: Vec<Ballot>,
}

impl InMemoryBulletinBoard {
    pub fn new() -> Self {
        Self {
            params: None,
            round1_outputs: Vec::new(),
            tallier_shares: Vec::new(),
            voter_registrations: Vec::new(),
            ballots: Vec::new(),
        }
    }
}

impl Default for InMemoryBulletinBoard {
    fn default() -> Self {
        Self::new()
    }
}
