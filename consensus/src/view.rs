#![allow(unused)]

use super::common::{SequenceNumber, View};
use super::state::{State, M};
use std::vec::Vec;
use themis::keys::EcdsaPublicKey;

/// Section 4.4 View Changes

#[derive(Clone)]
// Message format: ⟨VIEW-CHANGE, v+1, n, C, P, i⟩_{σ_i} (signed by replicas)
pub struct ViewChangeMessage {
    // Replica identity
    i: String,

    // The new view the replica proposes to move the system into; v+1, where v is
    // the current view
    next_view: View,

    // The sequence number of the last stable checkpoint known to the replica
    n: SequenceNumber,

    // A set C of (at least) 2F+1 valid checkpoint messages proving the last
    // stable checkpoint is valid
    big_c: Vec<CheckPoint>,

    // A set P containing sets P_m for each request `m` that prepared at
    // replica `i` with sequence number greater than `n`. In other words,
    // the inner fields of P_m needs to have sequence numbers greater than
    // the local sequence number of this struct.
    big_p: Vec<P>,
}
impl ViewChangeMessage {
    pub fn new(
        i: String,
        next_view: View,
        n: SequenceNumber,
        big_c: Vec<CheckPoint>,
        big_p: Vec<P>,
    ) -> Self {
        Self {
            i,
            next_view,
            n,
            big_c,
            big_p,
        }
    }

    pub fn next_view(&self) -> View {
        self.next_view.clone()
    }

    pub fn n(&self) -> SequenceNumber {
        self.n
    }

    pub fn big_p(&self) -> Vec<P> {
        self.big_p.clone()
    }
}

#[derive(Clone)]
pub struct CheckPoint {
    // Replica identity
    i: String,
    // The sequence number in the last request reflected in d
    n: SequenceNumber,
    // The message digest of the state; same as the message digest in `M`
    d: String,
}
impl CheckPoint {
    pub fn new(i: String, n: SequenceNumber, d: String) -> Self {
        Self { i, n, d }
    }

    pub fn data(self) -> String {
        self.d.clone()
    }
}

#[derive(Clone)]
// Prepared set: a quorum of pre-prepares
pub struct P {
    // A valid pre-preprepare message (without the corresponding request)
    valid_preprepare: Option<M>,
    // 2F matching prepare messages from other unique replicas.
    matching_prepares: Vec<M>,
}
impl P {
    pub fn new() -> Self {
        Self {
            valid_preprepare: None,
            matching_prepares: Vec::new(),
        }
    }

    pub fn insert_valid(&mut self, m: M) {
        if m.phase != State::new(1) {
            panic!("must insert preprepares as state");
        }
        self.valid_preprepare = Some(m);
    }

    pub fn insert_matching(&mut self, m: M) {
        if m.phase != State::new(2) {
            panic!("must insert prepares as state");
        }
        self.matching_prepares.push(m);
    }

    pub fn message(self) -> M {
        if self.matching_prepares.len() < 1 {
            panic!("this should not happen (matching prepares nil)");
        }
        self.matching_prepares[0].clone()
    }
}

struct BigO {
    // From the set V, the primary creates a new pre-prepare message for the next view v+1
    // for each sequence number `n` between `min-s` and `max-s`.
    // `min-s`: the sequence number for the latest stable checkpoint in V
    // `max-s`: the sequence number for the highest sequence number in a pre-prepare message in V
    new_view_preprepares: Vec<M>,
}
impl BigO {
    fn new(new_view_preprepares: Vec<M>) -> Self {
        Self {
            new_view_preprepares,
        }
    }
}

fn determine_min_max_s(big_v: &Vec<ViewChangeMessage>) -> (SequenceNumber, SequenceNumber) {
    if big_v.len() < 1 {
        panic!("cannot determine min-max-s due to empty view change log");
    }

    let mut min_s = u64::MAX;
    let mut max_s = u64::MIN;

    for iter in big_v.iter() {
        // scan the replica's P-set to look for the highest sequence number
        let repl_max_n = determine_max_prepare_n(iter.big_p.clone());
        // save the current highest sequence number as we know
        if repl_max_n > max_s {
            max_s = repl_max_n;
        }

        // latest stable checkpoint in V
        if iter.n < min_s {
            min_s = iter.n.clone();
        }
    }

    if min_s == max_s {
        panic!("min_s and max_s should not be equal");
    }

    (min_s, max_s)
}

fn determine_max_prepare_n(preprepares: Vec<P>) -> SequenceNumber {
    let max: SequenceNumber = 0;
    let max: SequenceNumber = preprepares
        .iter()
        .map(|p| p.matching_prepares[0].n)
        .max()
        .unwrap_or(0);
    if max == 0 {
        log::debug!("couldn't find a max sequence number, make sure to supply a valid P-set!");
    }
    max
}

// From a vector-of-vectors (a vector P containing vector P_m's), we extract a single vector with
// updated view (the next one) and
fn new_preprepare_message(
    big_v: &BigV,
    min_s: SequenceNumber,
    max_s: SequenceNumber,
    i: String,
) -> Vec<M> {
    let mut res = Vec::<M>::new();
    // There are two cases for how to create the next preprepare message based on the set V:
    //   (1) there is a P with a sequence number `n` s.t. min_s <= n <= max_s.
    //       In this case, increment the view and keep the rest of the message.
    //   (2) there is not a P with a sequence number `n` within this range.
    //       In this case, increment the view and modify the message digest
    //       to the one of a special null request.

    for iter in big_v.valid_vc_rcv.iter().clone() {
        let targ_n = iter.big_p[0].matching_prepares[0].clone().n;
        if targ_n >= min_s && targ_n <= max_s {
            let case_1_message = inc_v(
                iter.i.clone(),
                iter.next_view.clone(),
                targ_n.clone(), // n_pp, where n_pp >= n_cp
                iter.big_p[0].matching_prepares[0].d.clone(),
            );
            // a new and valid pp-message is created (carried over to the next view) if its sequence number
            // is within the min-max-s range
            res.push(case_1_message);
        } else {
            // a new dummy pp-message is created (and carried over to the next view) since
            // its sequence number is not within the min-max-range
            let case_2_message =
                inc_v_and_no_op(iter.i.clone(), iter.next_view.clone(), targ_n.clone());
            res.push(case_2_message);
        }
    }

    res
}

// Creates a new PREPREPARE message with an incremented view
fn inc_v(i: String, v: View, n: SequenceNumber, d: String) -> M {
    M::new(State::new(1), i, v + 1, n, d)
}

// Creates a new PREPREPARE message with an incremented view and a special null request (no-op)
fn inc_v_and_no_op(i: String, v: View, n: SequenceNumber) -> M {
    M::new(State::new(1), i, v + 1, n, String::from("NOOP"))
}

// V is a set with valid VIEW CHANGE messages receive by the primary plus the view change message
// the primary sent for view `v`+1 (or would have sent)
pub struct BigV {
    sent: Option<ViewChangeMessage>,
    valid_vc_rcv: Vec<ViewChangeMessage>,
}
impl BigV {
    fn new(vvc: Vec<ViewChangeMessage>) -> Self {
        Self {
            sent: None,
            valid_vc_rcv: vvc,
        }
    }
    fn insert_sent(mut self, vc: ViewChangeMessage) {
        self.sent = Some(vc);
    }
}

// Message format: ⟨NEW-VIEW, v+1, V, O⟩_{σ_P} (signed by primary)
pub struct NewViewMessage {
    // The new view the primary has received consensus on to move into; v+1.
    v: View,

    // A set V with the valid view-change messages received by the primary plus
    // its own already sent (or to be sent) message.
    big_v: BigV,

    // A set O with preprepares computed in a particular way.
    big_o: BigO,
}
impl NewViewMessage {
    pub fn new(v: View, big_v: BigV, i: String) -> Self {
        if big_v.valid_vc_rcv.len() < 4 {
            panic!("need at least a quorum of view change messages to construct new view message");
        }

        let (min_s, max_s) = determine_min_max_s(&big_v.valid_vc_rcv);
        let vec_m = new_preprepare_message(&big_v, min_s, max_s, i);
        Self {
            v,
            big_v,
            big_o: BigO::new(vec_m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcommons::generate_keys_as_str;
    use std::iter::Map;

    const DIG: &str = "dig"; // digest
    const ALICE: &str = "Alice"; // address from

    fn create_quorum_checkpoints(faulty: u8, n: SequenceNumber, d: &str) -> Vec<CheckPoint> {
        let mut vcp: Vec<CheckPoint> = Vec::new();
        let keys = generate_keys_as_str(2 * faulty + 1);
        for i in 0..2 * faulty + 1 {
            vcp.push(CheckPoint::new(keys[i as usize].clone(), n, d.to_string()));
        }
        vcp
    }

    fn create_quorum_preprepares(faulty: u8, v: View, n: SequenceNumber, d: &str) -> Vec<P> {
        let mut vpp: Vec<P> = Vec::new();
        for i in 0..2 * faulty + 1 {
            let mut p = P::new();
            p.insert_valid(M::new(State::new(1), i.to_string(), v, n, d.to_string()));
            for i in 0..2 * faulty + 1 {
                p.insert_matching(M::new(State::new(2), i.to_string(), v, n, d.to_string()));
            }
            vpp.push(p);
        }

        vpp
    }

    // curr_v: the view which the primary currently is in
    // n_cp: the sequence number of the checkpoint quorum
    // n_pp: the sequence number of the preprepare quorum
    // validator_set: the committee set / validators
    // faulty: the `f` out of the total replicas n = 3f + 1
    // amount: the amount of view change messages to create, bounded by `n`
    fn create_view_change_message(
        curr_v: View,
        n_cp: SequenceNumber,
        n_pp: SequenceNumber,
        d: &str,
        validator_set: Vec<String>,
        faulty: usize,
        amount: usize,
    ) -> Vec<ViewChangeMessage> {
        let mut res: Vec<ViewChangeMessage> = Vec::new();
        for i in 0..amount {
            let f = faulty as u8;
            let big_c = create_quorum_checkpoints(f, n_cp, &d);
            let big_p =
                create_quorum_preprepares(f, curr_v /* proofs for current view */, n_pp, d);
            let vc = ViewChangeMessage::new(
                validator_set[i].clone(),
                curr_v,
                n_cp, /* n_cp is derived from the quorum for n in C */
                big_c,
                big_p,
            );
            res.push(vc);
        }
        res
    }

    #[test]
    fn create_new_view_message() {
        let mut all_vc_m: Vec<ViewChangeMessage> = Vec::new();
        let vals: Vec<String> = vec!["A", "B", "C", "D"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        // begin add VC messages for a happy case where n_cp = n_pp, i.e. O set will include all
        // messages and there is no cut-off based on min_s and max_s
        let vc_m = create_view_change_message(1, 1, 1, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(1, 3, 3, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(1, 4, 4, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(1, 6, 6, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(1, 7, 7, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);

        let nv_message = NewViewMessage::new(1, BigV::new(all_vc_m), ALICE.to_string());
        let length = nv_message.big_o.new_view_preprepares.len();
        assert_eq!(5, length);
        let expected_view = 2;
        let expected_n_seq = vec![1, 3, 4, 6, 7];
        for i in 0..length {
            let actual_view = nv_message.big_o.new_view_preprepares[i].v;
            let actual_nonce = nv_message.big_o.new_view_preprepares[i].n;
            let actual_digest = nv_message.big_o.new_view_preprepares[i].d.clone();
            let expected_nonce = expected_n_seq[i];
            assert_eq!(expected_view, actual_view);
            assert_eq!(expected_nonce, actual_nonce);
            assert_eq!(DIG, actual_digest);
        }

        let mut all_vc_m: Vec<ViewChangeMessage> = Vec::new();
        // add VC messages for a case with messages n_cp_stable <= n_pp which means that
        // certain messages will be reverted to a no-op due to not fresh enough.
        //
        // In this case we will have a min_s = n_cp = 4 and a max_s = n_pp = 8. This implies that
        // sequence numbers less than 4 will be deemed invalid, which we have two of.
        let vc_m = create_view_change_message(2, 3, 4, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(2, 3, 1, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(2, 3, 2, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(2, 4, 4, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(2, 4, 5, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);
        let vc_m = create_view_change_message(2, 4, 8, DIG, vals.clone(), 2, 1);
        all_vc_m.extend(vc_m);

        let nv_message = NewViewMessage::new(2, BigV::new(all_vc_m), ALICE.to_string());
        let length = nv_message.big_o.new_view_preprepares.len();
        assert_eq!(6, length);
        let expected_view = 3;
        let expected_n_seq = vec![4, 1, 2, 4, 5, 8];
        let expected_digests = vec![DIG, "NOOP", "NOOP", DIG, DIG, DIG];
        for i in 0..length {
            let actual_view = nv_message.big_o.new_view_preprepares[i].v;
            let actual_nonce = nv_message.big_o.new_view_preprepares[i].n;
            let actual_digest = nv_message.big_o.new_view_preprepares[i].d.clone();
            let expected_nonce = expected_n_seq[i];
            assert_eq!(expected_view, actual_view);
            assert_eq!(expected_nonce, actual_nonce);
            assert_eq!(expected_digests[i], actual_digest);
        }
    }

    #[test]
    #[should_panic]
    fn create_invalid_new_view_message() {
        let vals: Vec<String> = vec!["A", "B", "C"] // less than 4 validators
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let vc_m = create_view_change_message(1, 1, 1, DIG, vals, 1, 1);
        let nv_message = NewViewMessage::new(1, BigV::new(vc_m), ALICE.to_string());
    }

    #[test]
    #[should_panic]
    fn create_invalid_big_o_message() {
        let mut p = P::new();
        p.insert_valid(M::new(
            State::new(0), /* ACCEPT REQUEST state instead of PREPREPARE (1) */
            ALICE.to_string(),
            1,
            0,
            DIG.to_string(),
        ));
    }

    #[test]
    #[should_panic]
    fn create_invalid_big_c_message() {
        let mut p = P::new();
        p.insert_matching(M::new(
            State::new(1), /* PREPREPARE state instead of PREPARE (2) */
            ALICE.to_string(),
            1,
            0,
            DIG.to_string(),
        ));
    }
}
