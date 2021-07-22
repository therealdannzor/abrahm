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
use themis::keys::EcdsaPublicKey;

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
    fn new(
        request: Option<Request>,
        preprepare: Option<M>,
        prepare: Option<M>,
        commit: Option<M>,
    ) -> Self {
        Self {
            request,
            preprepare,
            preprepare_sigs: Vec::new(),
            prepare,
            prepare_sigs: Vec::new(),
            commit,
            commit_sigs: Vec::new(),
        }
    }
    fn set_request(&mut self, request: Option<Request>) {
        self.request = request;
    }
    fn set_preprepare(&mut self, message: Option<M>) {
        self.preprepare = message;
    }
    fn set_prepare(mut self, message: M) {
        self.prepare = Some(message);
    }
    fn set_commit(&mut self, message: Option<M>) {
        self.commit = message;
    }
    fn add_preprepare_sig(&mut self, message: M) {
        self.preprepare_sigs.push(message);
    }
    fn add_prepare_sig(mut self, message: M) {
        self.prepare_sigs.push(message);
    }
    fn add_commit_sig(&mut self, message: M) {
        self.commit_sigs.push(message);
    }
}
impl AsRef<AckMessagesView> for AckMessagesView {
    fn as_ref(&self) -> &AckMessagesView {
        self
    }
}

impl Engine {
    // prepared orders requests in a view. Returns Ok if the predicate is true.
    pub fn prepared(&self, m: Request, v: View, n: SequenceNumber) -> Result<(), std::io::Error> {
        if self.message_log.get(&self.val_engine.view()).is_none()
            || self.message_log.get(&v).is_none()
        {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing message store for engine or param view",
            ));
        }

        let ack_m_engine_v = self.message_log.get(&self.val_engine.view()).unwrap();
        let ack_m_param_v = self.message_log.get(&v).unwrap();

        // (Section 4.2) Normal-Case Operation.
        // The predicate _prepared(m,v,n,i)_ is true iff the replica has inserted the request in its log
        if ack_m_engine_v.request.is_none() {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing proposed request in message store",
            ));
        // A pre-prepare for the request in the same `v` and `n`
        } else if ack_m_param_v.preprepare.is_some() {
            // check if the view of the stored preprepare message is the same as what we expect
            if v != ack_m_engine_v.preprepare.as_ref().unwrap().v {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "preprepare view is different from expected param view",
                ));
            // and do the same with the sequence number `n`
            } else if n != ack_m_param_v.preprepare.as_ref().unwrap().n {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "preprepare sequence number is different from expected param number",
                ));
            }
        } else {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing preprepare in message store",
            ));
        }

        if !correct_message_set(
            ack_m_param_v.preprepare.clone(),
            ack_m_param_v.preprepare_sigs.to_owned(),
            gt_two_thirds(ack_m_param_v.preprepare_sigs.len()),
        ) {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "non-matching preprepares in set or not enough messages to form quorum",
            ));
        }

        Ok(())
    }

    // committed is the final check before we finalize consensus on a request `m`.
    // Returns Ok if the predicate is true and there is a consensus agreement on `m`.
    // This method includes both the `committed` and `committed-local` predicate.
    fn committed(&self, m: Request, v: View, n: SequenceNumber) -> Result<(), std::io::Error> {
        if self.message_log.get(&self.val_engine.view()).is_none()
            || self.message_log.get(&v).is_none()
        {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing message store for engine or param view",
            ));
        } else if self.message_log.get(&v).unwrap().commit.is_none() {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing local commit",
            ));
        }

        let ack_m_param_v = self.message_log.get(&v).as_ref().unwrap().clone();

        // (Section 4.2) Normal-Case Operation.
        // The predicate _committed(m,v,n)_ is true iff:

        // If prepared is true for all i in a set of F+1 non-faulty replicas. By calling prepared,
        // we do not need to check preprepare and prepare messages.
        if self.prepared(m, v, n).is_err() {
            return Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "cannot check for committed state without first being in prepared state",
            ));
        } else {
            // check that we are on the same view and sequence number
            if ack_m_param_v.commit.clone().unwrap().n == n
                && ack_m_param_v.commit.clone().unwrap().v == v
            {
                // check if the view of the stored preprepare is the same as what we expect
                if !correct_message_set(
                    ack_m_param_v.commit.clone(),
                    ack_m_param_v.commit_sigs.to_owned(),
                    gt_two_thirds(ack_m_param_v.commit_sigs.len()),
                ) {
                    return Err(std::io::Error::new(
                        ErrorKind::NotFound,
                        "not enough matching commits",
                    ));
                }
                return Ok(());
            } else {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "cannot check for committed state when the proposed commit state differs from param",
                ));
            }
        }
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
                    if self
                        .prepared(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
                    {
                        unimplemented!(
                            "verify that we have quorum of preprepares and move to prepare"
                        );
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not prepared yet"));
                    }
                } else if msg_log.preprepare_sigs.len() > 0 {
                    let sequence_number = msg_log.preprepare_sigs[0].n;
                    if self
                        .prepared(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
                    {
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
                    if self
                        .committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
                    {
                        unimplemented!("verify that we have a quorum of prepares move to commit");
                    } else {
                        return Err(std::io::Error::new(ErrorKind::Other, "not prepared yet"));
                    }
                } else if self.message_log.get(&curr_view).unwrap().commit_sigs.len() > 0 {
                    let sequence_number = msg_log.prepare_sigs[0].n;
                    if self
                        .committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
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
                    if self
                        .committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
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
                    if self
                        .committed(msg_log_request.clone().unwrap(), curr_view, sequence_number)
                        .is_ok()
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

    fn process_request(&mut self) -> bool {
        let curr_view = self.val_engine.view();
        let _req = &self.message_log.get(&curr_view).as_ref().unwrap().request;
        true
    }

    pub fn new(id: EcdsaPublicKey, validators: Vec<EcdsaPublicKey>) -> Self {
        let mut message_log: HashMap<u64, AckMessagesView> = HashMap::new();
        message_log.insert(0, AckMessagesView::new(None, None, None, None));
        Self {
            val_engine: ValidatorProcess::new(id, validators),
            stable_checkpoint: 0,
            latest_checkpoint: 0,
            working_buffer: std::vec::Vec::new(),
            message_log,
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

mod tests {
    use super::*;
    use crate::consensus::testcommons::generate_keys;
    use crate::consensus::transition::{Transact, Transition};
    use themis::keys::EcdsaPublicKey;
    use tokio_test::{assert_err, assert_ok};

    fn create_request_type(
        account: &str,
        from: EcdsaPublicKey,
        to: EcdsaPublicKey,
        amount: i32,
    ) -> Request {
        let next_transition =
            Transition::new(String::from("0x"), vec![Transact::new(from, to, amount)]);
        Request::new(next_transition, "id")
    }

    fn create_message(state: u8, id: &str, view: u64, seq: u64, data: &str) -> M {
        M::new(
            State::new(state),
            String::from(id),
            view,
            seq,
            String::from(data),
        )
    }

    fn create_signatures(amount: u8, state: u8, view: u64, seq: u64, data: &str) -> Vec<M> {
        let mut result = Vec::new();
        for i in 0..amount {
            result.push(create_message(state, "id", view, seq, data));
        }
        result
    }

    fn setup() -> Engine {
        let keys = generate_keys(4);
        Engine::new(keys[0].clone(), keys)
    }

    #[test]
    fn prepared_and_committed_predicate_single_view_and_seq() {
        let mut engine = setup();
        let vals = engine.val_engine.set();
        let mut r1 = create_request_type("0x", vals[0].clone(), vals[1].clone(), 1);
        let view = 0;
        let seq_no = 0;

        // failing due to missing request
        assert_err!(engine.prepared(r1.clone(), view, seq_no));

        // add request
        engine
            .message_log
            .get_mut(&view)
            .unwrap()
            .set_request(Some(r1.clone()));

        // failing due to missing preprepare
        assert_err!(engine.prepared(r1.clone(), view, seq_no));

        // add preprepare message
        let msg_type = 1; // preprepare
        let message = create_message(msg_type, "0x", view, seq_no, "data");
        engine
            .message_log
            .get_mut(&view)
            .unwrap()
            .set_preprepare(Some(message));

        // failing due to missing signatures
        assert_err!(engine.prepared(r1.clone(), view, seq_no));

        // add preprepare signatures
        let amount = 4;
        let mut sigs = create_signatures(amount, msg_type, view, seq_no, "data");
        for i in 0..amount {
            engine
                .message_log
                .get_mut(&view)
                .unwrap()
                .add_preprepare_sig(sigs.pop().unwrap());
        }

        // prepared ok
        assert_ok!(engine.prepared(r1.clone(), view, seq_no));

        // failing due to missing commit message
        assert_err!(engine.committed(r1.clone(), view, seq_no));

        // add commit message
        let msg_type = 3; // commit
        let message = create_message(msg_type, "0", view, seq_no, "data");
        engine
            .message_log
            .get_mut(&view)
            .unwrap()
            .set_commit(Some(message));

        assert_err!(engine.committed(r1.clone(), view, seq_no));

        // add commit signatures
        let amount = 4;
        let mut sigs = create_signatures(amount, msg_type, view, seq_no, "data");
        for i in 0..amount {
            engine
                .message_log
                .get_mut(&view)
                .unwrap()
                .add_commit_sig(sigs.pop().unwrap());
        }

        assert_ok!(engine.prepared(r1.clone(), view, seq_no));
    }
}
