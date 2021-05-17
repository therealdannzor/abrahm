#![allow(unused)]

use crate::consensus::common::{Committer, SequenceNumber, ValidatorSet, View};
use crate::consensus::messages_tp::{Commit, Prepare, Preprepare};
use crate::consensus::request::Request;
use std::collections::HashMap;
use std::vec::Vec;

// Engine is the second highest abstraction of the consensus engine (after Consensus) which contains
// all the neccessary information for a validator to participate in a the replication process.
//
// The scope of this struct is exclusively the PBFT protocol.
pub struct Engine {
    // The latest view, from the perspective of the client
    v: View,

    // The nodes part of the consensus process.
    val_set: ValidatorSet,

    // The last point where messages up to this sequence number are finalized, i.e. there is a consensus.
    // This is strictly less than or equal to the latest checkpoint.
    stable_checkpoint: u64,

    // The most recent checkpoint confirmed.
    latest_checkpoint: u64,
}

impl Engine {
    pub fn new(validators: ValidatorSet) -> Self {
        Self {
            v: 0,
            val_set: validators,
            stable_checkpoint: 0,
            latest_checkpoint: 0,
        }
    }

    pub fn inc_v(mut self) {
        self.v = self.v + 1;
    }

    pub fn inc_stable_cp(mut self) {
        self.stable_checkpoint = self.stable_checkpoint + 1;
    }

    pub fn inc_latest_cp(mut self) {
        self.latest_checkpoint = self.latest_checkpoint + 1;
    }
}
