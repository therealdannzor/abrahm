#![allow(unused)]

use super::common::{Committer, ValidatorSet, View};
use super::state::State;
use std::vec::Vec;

/// Leader Election Process

// ValidatorEngine assigns and and manages the primary (leader) in the replication process.
// Sometimes this replica will be the primary but it is not a guarantee. The engine
// participates in making sure that all replicas agree on the same primary at the same time.
//
// In PBFT, the primary is replaced to make sure the system can guarantee liveness. But only if
// the system is not progressing and comes to a decision to execute a certain request within time.
// This approach can be called to have a "sticky leader" as opposed to changing the elected leader
// periodically in a consistent manner.
pub struct ValidatorEngine {
    // Replica id
    id: Committer,

    // The latest view as far as this replica is concerned.
    view: View,

    // The replica which starts the normal-case operation of sending a pre-prepare message with
    // a request. Note that the primary does not have to be the one who actually proposes the
    // request but assigns a sequence number to it and signs it. The other replicas will, in
    // accordance to the leader election protocol, recognize the replica's authority and respond
    // to it (assumed it is honest and responsive).
    primary: Committer,

    // Contains the set of validators that can participate in the validation and
    // proposal of requests. This set must be identical for all validators or else there will
    // be a discrepancy in choice of leaders. We assume it is ordered somehow and identitcal
    // to all replicas.
    set: ValidatorSet,

    // The current phase of the algorithm: ACCEPT REQUESTS, PREPREPARE, PREPARE, COMMIT,
    // VIEW-CHANGE, and NEW-VIEW.
    phase: State,

    // When this flag is enabled, the replica is in the normal operational mode with receiving and
    // sending messages as part of the three phase consensus. If this flag is disabled (false),
    // that means that its timer has expired and that it cannot proceed. Consequently, it its no
    // longer in normal mode and desires to start negotiating a view change with the other
    // replicas.
    normal_mode: bool,
}

impl ValidatorEngine {
    // Check whether this replica was a primary at a view
    pub fn is_primary_at_view(&self, v: View) -> bool {
        self.id == self.get_primary_at_view(v)
    }

    // Retrieve the primary at a view
    pub fn get_primary_at_view(&self, v: View) -> Committer {
        let size = self.set.len();
        let v = v as usize;
        self.set[v % size].clone()
    }

    // Rotate primary to the next one
    pub fn next_primary(mut self) {
        let size = self.set.len();
        let v = self.view as usize;
        self.primary = self.set[v % size].to_string(); // p = v mod |R|
    }

    pub fn is_primary(self) -> bool {
        self.id == self.primary
    }

    pub fn is_normal(self) -> bool {
        self.normal_mode
    }

    pub fn phase(self) -> State {
        self.phase
    }

    pub fn primary(self) -> Committer {
        self.primary
    }

    pub fn id(self) -> Committer {
        self.id
    }

    pub fn view(self) -> View {
        self.view
    }

    pub fn new(id: String, set: Vec<Committer>) -> Self {
        Self {
            id,
            view: 0,
            primary: set[0].to_string(),
            set,
            phase: State::init(),
            normal_mode: true,
        }
    }
}
