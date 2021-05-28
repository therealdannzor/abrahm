#![allow(unused)]

use crate::consensus::request::Request;
use std::{collections::HashMap, sync::mpsc, vec::Vec};

use super::common::{
    correct_message_set, count_votes, digest_m, filter_phase, filter_view, gt_two_thirds,
    Committer, SequenceNumber, ValidatorSet, View,
};
pub use super::state::{State, M};
use super::view::{CheckPoint, ViewChangeMessage};

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

    // Collection of replica messages by view.
    message_log: HashMap<View, AckMessagesView>,

    // Collection of checkpoint messages by sequence number.
    checkpoint_log: HashMap<SequenceNumber, Vec<CheckPoint>>,

    // Collection of view change messages retrieved by the sequence number of
    // the latest stable checkpoint.
    viewchange_log: HashMap<SequenceNumber, ViewChangeMessage>,

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

impl Engine {
    // prepared orders requests in a view. Returns true when the predicate is true.
    fn prepared(&self, m: Request, v: View, n: SequenceNumber) -> bool {
        // (Section 4.2) Normal-Case Operation.
        // The predicate _prepared(m,v,n,i)_ is true iff:

        // The replica has inserted the request in its log
        if self.message_log.get(&self.v).unwrap().request.is_none() {
            log::debug!("phase: preprepare, predicate failed due to missing request in log");
            return false;
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
                return false;
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
        } else {
            log::debug!("phase: preprepare, predicate failed due to missing preprepare in log");
            return false;
        }

        if !correct_message_set(
            self.message_log
                .get(&v)
                .as_ref()
                .unwrap()
                .preprepare
                .clone(),
            self.message_log
                .get(&v)
                .as_ref()
                .unwrap()
                .prepare_sigs
                .to_owned(),
            gt_two_thirds(
                self.message_log
                    .get(&v)
                    .as_ref()
                    .unwrap()
                    .prepare_sigs
                    .len(),
            ),
        ) {
            log::debug!("phase: {}, predicate failed due to non-matching preprepare in prepare set or not sufficient amount of messages, expected: {:?}, got: {:?}",
                "preprepare", self.message_log.get(&v).as_ref().unwrap().prepare.clone(), self.message_log.get(&v).as_ref().unwrap().preprepare_sigs.to_owned());
            return false;
        }

        true
    }

    // committed is the finally check before we finalize consensus on a request `m`.
    // Returns true if there is a consensus agreement on `m`.
    // It takes ownership of self but uses a reference to self through prepared.
    fn committed(self, m: Request, v: View, n: SequenceNumber) -> bool {
        // (Section 4.2) Normal-Case Operation.
        // The predicate _committed(m,v,n)_ is true iff:

        // If prepared is true for all i in a set of F+1 non-faulty replicas. By calling prepared,
        // we do not need to check preprepare and prepare messages.
        if !self.prepared(m, v, n) {
            log::debug!(
                "phase: preprepare, predicate failed since it needs to be in prepare state before asserting committed"
            );
            return false;
        } else {
            // A pre-preprepare for the request in the same `v` and `n`
            if self.message_log.get(&v).unwrap().commit.is_some() {
                // check if the view of the stored preprepare is the same as what we expect
                if !correct_message_set(
                    self.message_log.get(&v).as_ref().unwrap().commit.clone(),
                    self.message_log
                        .get(&v)
                        .as_ref()
                        .unwrap()
                        .commit_sigs
                        .to_owned(),
                    gt_two_thirds(self.message_log.get(&v).as_ref().unwrap().commit_sigs.len()),
                ) {
                    log::debug!("phase: prepare, predicate failed due to not enough matching commits, expected: {:?}, got{:?}",
                        self.message_log.get(&v).as_ref().unwrap().commit, self.message_log.get(&v).as_ref().unwrap().commit_sigs,
                        );
                    return false;
                }
            } else {
                log::debug!("phase: prepare, predicate failed due to missing local commit");
                return false;
            }
        }
        true
    }

    // valid_preprepare checks if the message is a valid preprepare
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
        let quorum = gt_two_thirds(n);

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
            checkpoint_log: HashMap::new(),
            viewchange_log: HashMap::new(),
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
