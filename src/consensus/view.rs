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

// Prepared set: a quorum of pre-prepares
pub struct P {
    // A valid pre-preprepare message (without the corresponding request)
    valid_preprepare: Option<M>,
    // 2F matching pre-prepare messages from other unique replicas.
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
        self.valid_preprepare = Some(m);
    }

    pub fn insert_matching(&mut self, m: M) {
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

fn determine_min_max_s(big_v: Vec<ViewChangeMessage>) -> (SequenceNumber, SequenceNumber) {
    if big_v.len() < 1 {
        panic!("cannot determine min-max-s due to empty view change log");
    }

    let mut min_s = u64::MIN;
    let mut max_s = u64::MIN;

    for (i, val) in big_v.iter().enumerate().clone() {
        if val.n > min_s {
            min_s = val.n.clone();
        } else if val.big_p[i].matching_prepares[i].n > max_s {
            max_s = val.big_p[i].matching_prepares[i].n;
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
    pub fn new(v: View, big_v: Vec<ViewChangeMessage>) -> Self {
        Self {
            v,
            big_v: Vec::new(),
            big_o: BigO::new(Vec::new()),
        }
    }
}
