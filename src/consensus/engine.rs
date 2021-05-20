#![allow(unused)]

use crate::consensus::common::{Committer, SequenceNumber, ValidatorSet, View};
use crate::consensus::messages_tp::{Commit, Prepare, Preprepare};
use crate::consensus::request::Request;
use std::collections::HashMap;
use std::sync::mpsc;
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

    // Consensus messages
    message_buffer: std::vec::Vec<M>,
}

// Phase messages (Preprepare, Prepare, Commit, ViewChange, NewView)
struct P(u16);
impl P {
    // Valid values:
    // 0 = PREPREARE
    // 1 = PREPARE
    // 2 = COMMIT
    // 3 = VIEWCHANGE
    // 4 = NEWVIEW
    // 5 = CHECKPOINT
    pub fn new(num: u16) -> Option<P> {
        if num < 6 {
            Some(P(num))
        } else {
            None
        }
    }
}

// Represents the format of all the consensus messages between peers
pub struct M {
    phase: P,
    id: String,
    v: View,
    d: String,
}

impl Engine {
    // TODO: expand with rest of the blockchain system only after internal consensus mechanism has
    // been completed and tested with a minimal working version
    pub fn start() -> (mpsc::Sender<M>, mpsc::Receiver<M>) {
        let (rx, tx): (mpsc::Sender<M>, mpsc::Receiver<M>) = mpsc::channel();
        (rx, tx)
    }

    pub fn new(validators: ValidatorSet) -> Self {
        Self {
            v: 0,
            val_set: validators,
            stable_checkpoint: 0,
            latest_checkpoint: 0,
            message_buffer: std::vec::Vec::new(),
        }
    }

    pub fn v(self) -> View {
        self.v
    }

    pub fn stable_cp(self) -> u64 {
        self.stable_checkpoint
    }

    pub fn latest_cp(self) -> u64 {
        self.latest_checkpoint
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
