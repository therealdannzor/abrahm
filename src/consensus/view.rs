#![allow(unused)]

use super::common::{SequenceNumber, View};
use super::state::M;
use std::vec::Vec;

/// Section 4.4 View Changes

// Message format: ⟨VIEW-CHANGE, v+1, n, C, P, i⟩_{σ_i} (signed by replicas)
pub struct ViewChangeMessage {
    // The identity of the replica
    i: String,

    // The new view the replica proposes to move the system into; v+1
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
    matching_preprepares: Vec<M>,
}
impl P {
    pub fn new() -> Self {
        Self {
            valid_preprepare: None,
            matching_preprepares: Vec::new(),
        }
    }

    pub fn insert_valid(&mut self, m: M) {
        self.valid_preprepare = Some(m);
    }

    pub fn insert_matching(&mut self, m: M) {
        self.matching_preprepares.push(m);
    }
}

// Message format: ⟨NEW-VIEW, v+1, V, O⟩_{σ_P} (signed by primary)
pub struct NewViewMessage {
    // The new view the primary has received consensus on to move into; v+1.
    v: View,

    // A set V with the valid view-change messages received by the primary plus
    // its own already sent (or to be sent) message.
    big_v: Vec<ViewChangeMessage>,

    // A set O with preprepares computed in a particular way (see impl).
    big_o: BigO,
}

struct BigO {}
impl BigO {}
