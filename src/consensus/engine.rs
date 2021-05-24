#![allow(unused)]

use crate::consensus::{
    common::{Committer, SequenceNumber, ValidatorSet, View},
    messages_tp::{Commit, Prepare, Preprepare},
    request::Request,
};
use std::{collections::HashMap, ops::Deref, sync::mpsc, vec::Vec};

// Engine is the second highest abstraction of the consensus engine (after Consensus) which contains
// all the neccessary information for a validator to participate in a the replication process.
//
// The scope of this struct is exclusively the PBFT protocol.
pub struct Engine {
    // The latest view, from the perspective of the client
    v: View,

    // The current phase the client is in as part of the consensus process
    current_phase: State,

    // The nodes part of the consensus process.
    val_set: ValidatorSet,

    // The last point where messages up to this sequence number are finalized, i.e. there is a consensus.
    // This is strictly less than or equal to the latest checkpoint.
    stable_checkpoint: u64,

    // The most recent checkpoint confirmed.
    latest_checkpoint: u64,

    // Consensus messages
    message_buffer: Vec<M>,
}

#[derive(Clone)]
// Phase messages
struct State(u8);
impl State {
    pub fn init() -> Self {
        Self(0)
    }

    // Valid values:
    // 0 = ACCEPT REQUESTS
    // 1 = PREPREPARE
    // 2 = PREPARE
    // 3 = COMMIT
    // 4 = VIEW CHANGE
    // 5 = NEW VIEW
    // 6 = CHECKPOINT
    pub fn change(mut self, num: u8) {
        if num < 7 {
            self.0 = num;
        } else {
            panic!("cannot create invalid state");
        }
    }

    pub fn parse(self) -> u8 {
        self.0
    }
}
impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Represents the format of all the consensus messages between peers
#[derive(Clone)]
pub struct M {
    phase: State,
    id: String,
    v: View,
    d: String,
}
impl Deref for M {
    type Target = u64; // View

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

// Filters all messages of the same view. We leave the input vector untouched.
fn filter_view(needle: View, haystack: Vec<M>) -> Vec<M> {
    let mut result: Vec<M> = Vec::new();
    for m in haystack.iter().clone() {
        if m.v == needle {
            result.push(m.clone());
        }
    }
    result
}

// Filters all messages in the same consensus phase. Does not modify input.
fn filter_phase(needle: State, haystack: Vec<M>) -> Vec<M> {
    let mut result: Vec<M> = Vec::new();
    for m in haystack.iter().clone() {
        if m.phase == needle {
            result.push(m.clone());
        }
    }
    result
}

// Returns true if all identities in the haystack are unique. Used to assert
// that the message set contains no duplicates.
fn is_unique(needle: State, haystack: Vec<M>) -> bool {
    let mut chk = HashMap::new();
    let num = needle.parse();
    for m in haystack.iter().clone() {
        if chk.contains_key(&num) {
            false;
        } else {
            chk.insert(&num, "dummy");
        }
    }
    true
}

// Returns the data payload (embedded in M) in which there have been most votes for
// and the amount of votes for it.
fn count_votes(haystack: Vec<M>) -> (String, usize) {
    let mut most_popular = String::from("");
    let mut most_amount = 0;
    let mut map = HashMap::new();
    for m in haystack.iter() {
        let c = map.entry(m.d.clone()).or_insert(0);
        *c += 1;
        if *c > most_amount {
            most_popular = m.d.clone();
        }
    }

    (most_popular, most_amount)
}

impl Engine {
    // Assert ageement of at least F+1 (>2/3) out of a total of N=3F+1 nodes.
    // Assumes that the message set is for a particular view.
    fn is_quorum(self, message_set: Vec<M>) -> Result<String, &'static str> {
        if self.val_set.len() < 4 {
            panic!("invalid validator set size, this should not happen");
        }

        // Make sure we have messages from:
        // unique peers
        let ft = is_unique(self.current_phase.clone(), self.message_buffer.clone());
        // in the same phase
        let ft = filter_phase(self.current_phase, self.message_buffer);
        // and in the same view.
        let ft = filter_view(self.v, ft);

        // total unique votes (N)
        let n = ft.len();

        // Total replicas:         N = 3F + 1
        // Maximum Byzantine:      F = (N - 1) / 3
        // Quorum:                 2F + 1
        let quorum = 2 * ((n - 1) / 3) + 1;

        let (vote, amount) = count_votes(ft);

        if amount >= quorum {
            Ok(vote)
        } else {
            Err("no quorum achieved")
        }
    }

    pub fn add_message(mut self, msg: M) {
        self.message_buffer.push(msg);
    }

    // TODO: expand with rest of the blockchain system only after internal consensus mechanism has
    // been completed and tested with a minimal working version
    pub fn start() -> (mpsc::Sender<M>, mpsc::Receiver<M>) {
        let (rx, tx): (mpsc::Sender<M>, mpsc::Receiver<M>) = mpsc::channel();
        (rx, tx)
    }

    pub fn new(validators: ValidatorSet) -> Self {
        Self {
            v: 0,
            current_phase: State::init(),
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
