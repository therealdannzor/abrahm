#![allow(unused)]

use super::common::{SequenceNumber, View};
use super::state::{State, M};
use std::vec::Vec;

/// Section 4.4 View Changes

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
}

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

    let mut min_s = u64::MIN;
    let mut max_s = u64::MIN;

    for (i, val) in big_v.iter().enumerate() {
        if val.n > min_s {
            min_s = val.n.clone();
        } else if val.big_p[i].matching_prepares[i].n > max_s {
            max_s = val.big_p[i].matching_prepares[i].n.clone();
        } else {
            log::debug!("couldn't find either min_s or max_s in vc vector");
        }
    }

    (min_s, max_s)
}

// From a vector-of-vectors (a vector P containing vector P_m's), we extract a single vector with
// updated view (the next one) and
fn new_preprepare_message(
    big_p: Vec<P>,
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

    for iter in big_p.iter().clone() {
        // the valid preprepare should contain the exact same information as in matching prepares
        if iter.valid_preprepare.clone().unwrap().n >= min_s
            && iter.valid_preprepare.clone().unwrap().n <= max_s
        {
            let case_1_message = inc_v(
                iter.valid_preprepare.clone().unwrap().i.clone(),
                iter.valid_preprepare.clone().unwrap().v.clone(),
                iter.valid_preprepare.clone().unwrap().n.clone(),
                iter.valid_preprepare.clone().unwrap().d.clone(),
            );
            res.push(case_1_message);
        } else {
            let case_2_message = inc_v_and_no_op(
                iter.valid_preprepare.clone().unwrap().i.clone(),
                iter.valid_preprepare.clone().unwrap().v.clone(),
                iter.valid_preprepare.clone().unwrap().n.clone(),
            );
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

// Message format: ⟨NEW-VIEW, v+1, V, O⟩_{σ_P} (signed by primary)
pub struct NewViewMessage {
    // The new view the primary has received consensus on to move into; v+1.
    v: View,

    // A set V with the valid view-change messages received by the primary plus
    // its own already sent (or to be sent) message.
    big_v: Vec<ViewChangeMessage>,

    // A set O with preprepares computed in a particular way.
    big_o: BigO,
}
impl NewViewMessage {
    pub fn new(v: View, big_v: Vec<ViewChangeMessage>, i: String) -> Self {
        if big_v.len() < 4 {
            panic!("need at least a quorum of view change messages to construct new view message");
        }

        let (min_s, max_s) = determine_min_max_s(&big_v);
        // assume P is identical at all replicas, only differed by order depending on when
        // they were received locally
        let vec_m = new_preprepare_message(big_v[0].big_p.clone(), min_s, max_s, i);
        Self {
            v,
            big_v: Vec::new(),
            big_o: BigO::new(vec_m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::Map;

    const DIG: &str = "dig"; // digest
    const ALICE: &str = "Alice"; // address from

    fn create_quorum_checkpoints(faulty: u8, n: SequenceNumber) -> Vec<CheckPoint> {
        let mut vcp: Vec<CheckPoint> = Vec::new();
        for i in 0..2 * faulty + 1 {
            vcp.push(CheckPoint::new(i.to_string(), n, DIG.to_string()));
        }
        vcp
    }

    fn create_quorum_preprepares(faulty: u8, v: View, n: SequenceNumber) -> Vec<P> {
        let mut vpp: Vec<P> = Vec::new();
        for i in 0..2 * faulty + 1 {
            let mut p = P::new();
            p.insert_valid(M::new(State::new(1), i.to_string(), v, n, DIG.to_string()));
            for i in 0..2 * faulty + 1 {
                p.insert_matching(M::new(State::new(2), i.to_string(), v, n, DIG.to_string()));
            }
            vpp.push(p);
        }

        vpp
    }

    fn generate_big_c_p_pair(faulty: u8, v: View, n: SequenceNumber) -> (Vec<CheckPoint>, Vec<P>) {
        (
            create_quorum_checkpoints(faulty, n),
            create_quorum_preprepares(faulty, v, n),
        )
    }

    fn create_view_change_message(
        curr_v: View,
        n: SequenceNumber,
        mut validator_set: Vec<String>,
        faulty: usize,
        amount: usize,
    ) -> Vec<ViewChangeMessage> {
        let v = curr_v + 1;
        let mut res: Vec<ViewChangeMessage> = Vec::new();
        for i in 0..amount {
            let f = faulty as u8;
            let (big_c, big_p) =
                generate_big_c_p_pair(f, curr_v /* proofs for current view */, n);
            let vc = ViewChangeMessage::new(
                validator_set[i].clone(),
                v, /* next view */
                n,
                big_c,
                big_p,
            );
            res.push(vc);
        }
        res
    }

    #[test]
    fn create_new_view_message() {
        let mut all_vc_messages: Vec<ViewChangeMessage> = Vec::new();
        let vals: Vec<String> = vec!["A", "B", "C", "D"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let vc_messages = create_view_change_message(1, 1, vals.clone(), 2, 1);
        all_vc_messages.extend(vc_messages);
        let vc_messages = create_view_change_message(1, 3, vals.clone(), 2, 1);
        all_vc_messages.extend(vc_messages);
        let vc_messages = create_view_change_message(1, 4, vals.clone(), 2, 1);
        all_vc_messages.extend(vc_messages);
        let vc_messages = create_view_change_message(1, 6, vals.clone(), 2, 1);
        all_vc_messages.extend(vc_messages);
        let vc_messages = create_view_change_message(1, 7, vals.clone(), 2, 1);
        all_vc_messages.extend(vc_messages);

        let nv_message = NewViewMessage::new(1, all_vc_messages, ALICE.to_string());
        let length = nv_message.big_o.new_view_preprepares.len();
        assert_eq!(5, length);
        let actual_view = nv_message.big_o.new_view_preprepares[0].v;
        let expected_view = 2;
        assert_eq!(expected_view, actual_view);
    }

    #[test]
    #[should_panic]
    fn create_invalid_new_view_message() {
        let vals: Vec<String> = vec!["A", "B", "C"] // less than 4 validators
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let vc_messages = create_view_change_message(1, 1, vals, 1, 1);
        let nv_message = NewViewMessage::new(1, vc_messages, ALICE.to_string());
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
