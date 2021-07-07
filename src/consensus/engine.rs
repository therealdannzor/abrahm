#![allow(unused)]

use crate::consensus::request::Request;
use std::{collections::HashMap, io::ErrorKind, vec::Vec};

use super::common::{
    correct_message_set, count_viewchange_votes, count_votes, digest_m, filter_phase, filter_view,
    filter_viewchange, gt_two_thirds, Committer, SequenceNumber, ValidatorSet, View,
};
use super::leader_process::ValidatorProcess;
pub use super::state::{State, M};
use super::view::{CheckPoint, ViewChangeMessage};

// Engine is the second highest abstraction of the consensus engine (after ConsensusChain) which contains
// all the neccessary information for a validator to participate in a the replication process.
//
// The scope of this struct is exclusively the PBFT protocol.
pub struct Engine {
    // ValidatorProcess drives the leader election process.
    //
    // In addition, it contains the ID of the replica, the current view, the primary of this and previous
    // views, the sets of validators, and the current PBFT phase.
    val_engine: ValidatorProcess,

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
    viewchange_log: HashMap<SequenceNumber, Vec<ViewChangeMessage>>,

    // Amount of time before resending a message
    timeout: std::time::Duration,

    // Only accept sequence numbers above this
    low_watermark: u64,

    // Only accept sequence numbers below this
    high_watermark: u64,
}

#[derive(Clone)]
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
impl AckMessagesView {
    fn new() -> Self {
        Self {
            request: None,
            preprepare: None,
            preprepare_sigs: Vec::new(),
            prepare: None,
            prepare_sigs: Vec::new(),
            commit: None,
            commit_sigs: Vec::new(),
        }
    }
    fn set_request(mut self, request: Request) {
        self.request = Some(request);
    }
    fn set_preprepare(mut self, message: M) {
        self.preprepare = Some(message);
    }
    fn set_prepare(mut self, message: M) {
        self.prepare = Some(message);
    }
    fn set_commit(mut self, message: M) {
        self.commit = Some(message);
    }
    fn add_preprepare_sig(mut self, message: M) {
        self.preprepare_sigs.push(message);
    }
    fn add_prepare_sig(mut self, message: M) {
        self.prepare_sigs.push(message);
    }
    fn add_commit_sig(mut self, message: M) {
        self.commit_sigs.push(message);
    }
}

impl Engine {
    // prepared orders requests in a view. Returns true when the predicate is true.
    fn prepared(&self, m: Request, v: View, n: SequenceNumber) -> bool {
        // (Section 4.2) Normal-Case Operation.
        // The predicate _prepared(m,v,n,i)_ is true iff:

        // The replica has inserted the request in its log
        if self
            .message_log
            .get(&self.val_engine.view())
            .unwrap()
            .request
            .is_none()
        {
            log::debug!("phase: preprepare, predicate failed due to missing request in log");
            return false;
        // A pre-prepare for the request in the same `v` and `n`
        } else if self.message_log.get(&v).unwrap().preprepare.is_some() {
            // check if the view of the stored preprepare message is the same as what we expect
            if v != self
                .message_log
                .get(&self.val_engine.view())
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
                        .get(&self.val_engine.view())
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
                        .get(&self.val_engine.view())
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
    fn committed(&self, m: Request, v: View, n: SequenceNumber) -> bool {
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
        } else if message.v != self.val_engine.view() {
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
        if self.val_engine.big_n() < 4 {
            panic!("invalid validator set size, this should not happen");
        }

        // Make sure we have messages from:
        // the same phase
        let ft = filter_phase(self.val_engine.phase(), self.working_buffer);
        // and the same view.
        let ft = filter_view(self.val_engine.view(), ft);

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

    fn is_viewchange_quorum(&self) -> Result<String, &'static str> {
        let vc = match self.viewchange_log.get(&self.val_engine.view()) {
            Some(vc) => Ok(vc),
            None => Err("view change log is empty"),
        };
        let vc = vc.unwrap();
        let curr_view = self.val_engine.view();
        let ft = filter_viewchange(curr_view, vc.to_vec());
        let n = ft.len();
        let quorum = gt_two_thirds(n);
        let (vote, amount) = count_viewchange_votes(vc.to_vec());

        if amount >= quorum {
            Ok(vote)
        } else {
            Err("no quorum achieved")
        }
    }

    fn insert_buffer_message(mut self, msg: M) {
        self.working_buffer.push(msg);
    }

    fn insert_message_log(mut self, view: View) {
        self.message_log.insert(view, AckMessagesView::new());
    }

    // TODO: integrate with the rest of the blockchain system only after internal consensus mechanism has
    // been completed and tested with a minimal working version
    //
    // process_consensus polls the leader process engine for the current status and changes state if the consensus
    // criteria are satisfied. If not, nothing changes. Instead of implementing this as an event-driven loop, this
    // method can combined with other higher level constructs as needed.
    pub fn process_consensus(&mut self) -> Result<(), std::io::Error> {
        let curr_view = self.val_engine.view();
        let curr_state = self.val_engine.phase();

        if self.working_buffer.len() < self.val_engine.quorum_threshold()
            || self.message_log.get(&curr_view).is_none()
        {
            return Err(std::io::Error::new(ErrorKind::Other, "not enough messages"));
        }

        let msg_log = self.message_log.get(&curr_view).unwrap();
        let msg_log_prepare = msg_log.prepare.clone();
        let msg_log_preprepare = msg_log.preprepare.clone();
        let msg_log_request = msg_log.request.clone();
        let msg_log_commit = msg_log.commit.clone();
        match curr_state.into_inner() {
            // accept messages
            0 => {
                if self.message_log.get(&curr_view).unwrap().request.is_some() {
                    unimplemented!("process request, and if valid, proceed to preprepare on it");
                } else {
                    return Err(std::io::Error::new(
                        ErrorKind::NotConnected,
                        "request not received/created yet",
                    ));
                }
            }
            // preprepare
            1 => {
                if msg_log_preprepare.clone().is_some() {
                    let sequence_number = msg_log_preprepare.as_ref().unwrap().n;
                    if self.prepared(msg_log_request.clone().unwrap(), curr_view, sequence_number) {
                        unimplemented!(
                            "verify that we have quorum of preprepares and move to prepare"
                        );
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not prepared yet"));
                    }
                } else if msg_log.preprepare_sigs.len() > 0 {
                    let sequence_number = msg_log.preprepare_sigs[0].n;
                    if self.prepared(msg_log_request.clone().unwrap(), curr_view, sequence_number) {
                        unimplemented!(
                            "verify that we have quorum of preprepares and move to prepare"
                        );
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not prepared yet"));
                    }
                }
            }
            // prepare
            2 => {
                if self.message_log.get(&curr_view).unwrap().prepare.is_some() {
                    let sequence_number = msg_log_prepare.as_ref().unwrap().n;
                    if self.committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                    {
                        unimplemented!("verify that we have a quorum of prepares move to commit");
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not prepared yet"));
                    }
                } else if self.message_log.get(&curr_view).unwrap().commit_sigs.len() > 0 {
                    let sequence_number = msg_log.prepare_sigs[0].n;
                    if self.committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                    {
                        unimplemented!("verify that we have a quorum of commits and commit the request as a block");
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not committed yet"));
                    }
                } else {
                    return Err(std::io::Error::new(
                        ErrorKind::Interrupted,
                        "waiting for any message, created or received",
                    ));
                }
            }
            // commit
            3 => {
                if self.message_log.get(&curr_view).unwrap().commit.is_some() {
                    let sequence_number = msg_log_commit.as_ref().unwrap().n;
                    if self.committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                    {
                        unimplemented!("broadcast that block has been committed and start consensus process from scratch");
                    } else {
                        return Err(std::io::Error::new(
                            ErrorKind::Interrupted,
                            "waiting for more messages or a quorum",
                        ));
                    }
                } else if msg_log.commit_sigs.len() > 0 {
                    let sequence_number = msg_log.commit_sigs[0].n;
                    if self.committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                    {
                        unimplemented!("broadcast that block has been committed and start consensus process from scratch");
                    } else {
                        return Err(std::io::Error::new(
                            ErrorKind::Interrupted,
                            "waiting for more messages or a quorum",
                        ));
                    }
                }
            }
            // view change
            4 => {
                let vc = self.viewchange_log.get(&curr_view);
                if vc.is_none() {
                    return Err(std::io::Error::new(
                        ErrorKind::Interrupted,
                        "waiting for additional view messages",
                    ));
                }
                let result = self.is_viewchange_quorum();
                if result.is_ok() {
                    unimplemented!("multicast new view message and move to the new view");
                } else {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        "no viewchange quorum yet",
                    ));
                }
            }
            // new view
            5 => {
                unimplemented!(
                    "redo the protocol for messages in min/max-s and obtain any missing CPs"
                );
            }
            // checkpoint
            6 => {
                if self.checkpoint_log.get(&curr_view).is_none() {
                    self.checkpoint_log.insert(curr_view, Vec::new());
                }
                self.checkpoint_log
                    .get(&curr_view)
                    .unwrap()
                    .clone()
                    .push(CheckPoint::new(
                        self.val_engine.id(),
                        msg_log_commit.clone().unwrap().n.clone(),
                        msg_log_commit.clone().unwrap().d.clone(),
                    ));
                unimplemented!("multicast checkpoint");
            }
            _ => panic!("this should never happen (process consensus)"),
        }

        Ok(())
    }

    pub fn new(id: String, validators: ValidatorSet) -> Self {
        Self {
            val_engine: ValidatorProcess::new(id, validators),
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

    pub fn stable_cp(self) -> u64 {
        self.stable_checkpoint
    }

    pub fn latest_cp(self) -> u64 {
        self.latest_checkpoint
    }

    pub fn inc_stable_cp(mut self) {
        self.stable_checkpoint = self.stable_checkpoint + 1;
    }

    pub fn inc_latest_cp(mut self) {
        self.latest_checkpoint = self.latest_checkpoint + 1;
    }
}
