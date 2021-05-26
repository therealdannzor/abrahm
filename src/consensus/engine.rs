#![allow(unused)]

use crate::consensus::{
    common::{Committer, SequenceNumber, ValidatorSet, View},
    messages_tp::{Commit, Prepare, Preprepare},
    request::Request,
};
use std::{collections::HashMap, ops::Deref, sync::mpsc, vec::Vec};

use super::common::{count_votes, digest_m, filter_phase, filter_view};

// Engine is the second highest abstraction of the consensus engine (after Consensus) which contains
// all the neccessary information for a validator to participate in a the replication process.
//
// The scope of this struct is exclusively the PBFT protocol.
pub struct Engine {
    // Latest view
    v: View,

    // Current phase
    current_phase: State,

    // Nodes able to validate blocks (active participators of the consensus process)
    val_set: ValidatorSet,

    // The last point where messages up to this sequence number are finalized, i.e. there is a consensus.
    // This is strictly less than or equal to the latest checkpoint.
    stable_checkpoint: u64,

    // The most recent checkpoint confirmed.
    latest_checkpoint: u64,

    // Temporary mem buffer, purged periodically.
    working_buffer: Vec<M>,

    // Log with replica messages
    message_log: HashMap<View, AckMessagesView>,

    // Amount of time before resending a message
    timeout: std::time::Duration,

    // Only accept sequence numbers above this
    low_watermark: u64,

    // Only accept sequence numbers below this
    high_watermark: u64,
}

// Accepted messages (Request, Preprepare, Prepare, Commit) for a view
struct AckMessagesView {
    // The operation being negotiated to perform. This is either created locally
    // by the replice, or is received as a proposal from another replica.
    request: Option<Request>,

    // Latest preprepare with the most fresh sequence number `n`. This field is used
    // to distinguish if (at least) a message has been broadcast by the local replica.
    preprepare: Option<M>,
    // Includes the latest preprepare and contains messages from other replicas.
    preprepare_sigs: Vec<M>,

    // Prepare phase
    prepare: Option<M>,
    prepare_sigs: Vec<M>,

    // Commit phase
    commit: Option<M>,
    commit_sigs: Vec<M>,
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
    pub phase: State,
    // identity of the replcia
    pub i: String,
    // provides liveness by allowing changes if (when) primary fails
    pub v: View,
    // order requests with consecutive sequence numbers for each replica
    pub n: SequenceNumber,
    // message digest
    pub d: String,
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

impl Deref for M {
    type Target = u64; // View

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl Engine {
    fn prepared(self, m: Request, v: View, n: SequenceNumber, i: String) -> bool {
        // (Section 4.2) Normal-Case Operation.
        // The predicate _prepared(m,v,n,i)_ is true iff:

        // The replica has inserted the request in its log
        if self.message_log.get(&self.v).unwrap().request.is_none() {
            log::debug!("phase: preprepare, predicate failed due to missing request in log");
            false;
        // A pre-prepare for the request in the same `v` and `n`
        } else if self.message_log.get(&v).unwrap().preprepare.is_some() {
            // check if the view of the stored preprepare message is the same as what we expect
            if v != self
                .message_log
                .get(&self.v)
                .unwrap()
                .preprepare
                .as_ref()
                .unwrap()
                .v
            {
                log::debug!(
                    "phase: {}, predicate failed due to `v`, expected: {}, got: {}",
                    "preprepare",
                    v,
                    self.message_log
                        .get(&self.v)
                        .unwrap()
                        .preprepare
                        .as_ref()
                        .unwrap()
                        .v
                );
                false;
            // and do the same with the sequence number `n`
            } else if n
                != self
                    .message_log
                    .get(&v)
                    .unwrap()
                    .preprepare
                    .as_ref()
                    .unwrap()
                    .n
            {
                log::debug!(
                    "phase: {}, predicate failed due to `n`, expected: {}, got: {}",
                    "preprepare",
                    n,
                    self.message_log
                        .get(&self.v)
                        .unwrap()
                        .preprepare
                        .as_ref()
                        .unwrap()
                        .v
                );
                return false;
            }
        } //TODO: add check that there are 2F prepares from different replicas that match the preprepare

        true
    }

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
        } else if self.message_log.contains_key(&message.v)
            && self
                .message_log
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
        let ft = filter_phase(self.current_phase, self.working_buffer);
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
        self.working_buffer.push(msg);
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
            working_buffer: std::vec::Vec::new(),
            message_log: HashMap::new(),
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
