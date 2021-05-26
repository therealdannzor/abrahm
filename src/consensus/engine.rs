#![allow(unused)]

use crate::consensus::{
    common::{Committer, SequenceNumber, ValidatorSet, View},
    messages_tp::{Commit, Prepare, Preprepare},
    request::Request,
};
use crate::{hashed, swiss_knife::helper::generate_hash_from_input};
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

    // View messages
    view_buffer: HashMap<View, AckMessagesView>,

    // Amount of time before resending a message
    timeout: std::time::Duration,

    // Only accept sequence numbers above this
    low_watermark: u64,

    // Only accept sequence numbers below this
    high_watermark: u64,
}

// Accepted messages (Preprepare, Prepare, Commit) for a view
struct AckMessagesView {
    preprepare: Option<M>,
    prepare: Option<M>,
    commit: Option<M>,
}

#[derive(Clone)]
// Phase messages
pub struct State(u8);
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
    pub fn new(num: u8) -> Self {
        if num < 7 {
            Self(num)
        } else {
            panic!("cannot create invalid state");
        }
    }

    pub fn into_inner(self) -> u8 {
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
    // denotes the type of the message
    phase: State,
    // identity of the replcia
    i: String,
    // provides liveness by allowing changes if (when) primary fails
    v: View,
    // order requests with consecutive sequence numbers for each replica
    n: SequenceNumber,
    // message digest
    d: String,
}
impl M {
    pub fn new(
        phase: State,
        i: String,
        v: View,
        n: SequenceNumber,
        digest_fn: fn(phase: State, i: String, v: View, n: SequenceNumber) -> String,
    ) -> Self {
        Self {
            phase: phase.clone(),
            i: i.clone(),
            v,
            n,
            d: digest_fn(phase, i, v, n),
        }
    }

    pub fn init(
        self,
        i: String,
        digest_fn: fn(phase: State, i: String, v: View, n: SequenceNumber) -> String,
    ) -> Self {
        Self {
            phase: State::init(),
            i: i.clone(),
            v: 0,
            n: 0,
            d: digest_fn(self.phase, i, 0, 0),
        }
    }

    fn mut_phase(mut self, phase: State) {
        self.phase = phase;
    }

    fn next_phase(mut self) {
        let curr = self.phase.into_inner();
        match curr {
            0 => self.phase = State::new(1), // proceed to PREPREPARE
            1 => self.phase = State::new(2), // proceed to PREPARE
            2 => self.phase = State::new(3), // proceed to COMMIT
            3 => self.phase = State::new(0), // proceed to ACCEPT REQUESTS
            _ => log::debug!("no next phase: given phase not part of 3-phase-consensus"),
        }
    }
}

// TODO: proper signing for each peer because as it stands now, it is possible
// for replicas to masquerade one another
fn digest_m(phase: State, i: String, v: View, n: SequenceNumber) -> String {
    let mut to_hash = "".to_string();
    to_hash.push_str(&phase.into_inner().to_string());
    to_hash.push_str(&v.to_string());
    to_hash.push_str(&n.to_string());
    hashed!(&to_hash.to_string())
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
    fn valid_preprepare(self, message: M) -> bool {
        // (Section 4.2) Normal-Case Operation.
        // A backup accepts a pre-prepare message provided:

        //   the signatures in the request and the pre-prepare
        //   messages are correct and `d` is the digest for `m`;
        if message.d != digest_m(message.phase, message.i, message.v, message.n) {
            false;

        //   it is in view `v`;
        } else if message.v != self.v {
            false;
        //   it has not accepted a pre-prepare message for view `v`
        //   and sequence number `n` containing a different digest;
        } else if self.view_buffer.contains_key(&message.v)
            && self
                .view_buffer
                .get(&message.v)
                .unwrap()
                .preprepare
                .is_some()
        {
            false;
        //   the sequence number in the pre-prepare message is between
        //   a low water mark `h`, and a high water mark, `H`.
        } else if message.n < self.low_watermark || message.n > self.high_watermark {
            false;
        }
        true
    }

    // Assert ageement of at least 2F+1 (>2/3) out of a total of N=3F+1 nodes.
    // Assumes that the message set is for a particular view and that we do not
    // accept duplicates to the message set.
    fn is_quorum(self, message_set: Vec<M>) -> Result<String, &'static str> {
        if self.val_set.len() < 4 {
            panic!("invalid validator set size, this should not happen");
        }

        // Make sure we have messages from:
        // the same phase
        let ft = filter_phase(self.current_phase, self.message_buffer);
        // and the same view.
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

    // TODO: integrate with the rest of the blockchain system only after internal consensus mechanism has
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
            view_buffer: HashMap::new(),
            timeout: std::time::Duration::from_secs(5), // initial guesstimate
            low_watermark: 0,
            high_watermark: 100, // initial guesstimate
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
