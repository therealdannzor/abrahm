#![allow(unused)]

use super::common::View;
use super::state::State;
use std::vec::Vec;
use themis::keys::EcdsaPublicKey;

#[derive(Clone)]
/// Leader Election Process

// ValidatorProcess assigns and and manages the primary (leader) in the replication process.
// Sometimes this replica will be the primary but it is not a guarantee. The engine
// participates in making sure that all replicas agree on the same primary at the same time.
//
// In PBFT, the primary is replaced to make sure the system can guarantee liveness. But only if
// the system is not progressing and comes to a decision to execute a certain request within time.
// This approach can be called to have a "sticky leader" as opposed to changing the elected leader
// periodically in a consistent manner.
pub struct ValidatorProcess {
    // Replica ID
    id: String,

    // The latest view as far as this replica is concerned.
    view: View,

    // Transaction nonce
    sequence_number: usize,

    // The replica which starts the normal-case operation of sending a pre-prepare message with
    // a request. Note that the primary does not have to be the one who actually proposes the
    // request but assigns a sequence number to it and signs it. The other replicas will, in
    // accordance to the leader election protocol, recognize the replica's authority and respond
    // to it (assumed it is honest and responsive).
    primary: String,

    // Contains the set of validators that can participate in the validation and
    // proposal of requests. This set must be identical for all validators or else there will
    // be a discrepancy in choice of leaders. We assume it is ordered somehow and identitcal
    // to all replicas.
    set: Vec<String>,

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

impl ValidatorProcess {
    // Check whether this replica was a primary at a view
    pub fn is_primary_at_view(&self, v: View) -> bool {
        self.id == self.get_primary_at_view(v)
    }

    // Retrieve the primary at a view
    pub fn get_primary_at_view(&self, v: View) -> String {
        let size = self.set.len();
        let v = v as usize;
        self.set[v % size].clone()
    }

    // Rotate primary to the next one based on view. This needs to be called after
    // a view change has occurred.
    pub fn next_primary(&mut self) {
        let size = self.set.len();
        let v = self.view as usize;
        self.primary = self.set[v % size].clone(); // p = v mod |R|
    }

    pub fn next_phase(&mut self) {
        self.phase.next();
    }

    pub fn is_primary(&self) -> bool {
        self.id == self.primary
    }

    pub fn is_normal(&self) -> bool {
        self.normal_mode
    }

    // Corresponds to N=3F+1
    pub fn big_n(&self) -> usize {
        self.set.len()
    }

    pub fn quorum_threshold(&self) -> usize {
        (((2f64) / (3f64)) * self.big_n() as f64).ceil() as usize
    }

    pub fn set(&self) -> Vec<String> {
        self.set.clone()
    }

    pub fn phase(&self) -> State {
        self.phase.clone()
    }

    pub fn primary(&self) -> String {
        self.primary.clone()
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn inc_v(&mut self) {
        self.view += 1;
    }

    pub fn view(&self) -> View {
        let v = self.view.clone();
        v
    }

    pub fn n(&self) -> usize {
        self.sequence_number.clone()
    }

    pub fn new(id: String, set: Vec<String>) -> Self {
        if set.len() < 3 {
            panic!("need at least 3 other validators");
        }

        Self {
            id,
            view: 0,
            sequence_number: 0,
            primary: set[0].clone(),
            set,
            phase: State::init(),
            normal_mode: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    use crate::testcommons::generate_keys_as_str_and_type;
    use std::iter::Iterator;
    use themis::keygen;

    #[test]
    fn leader_rotation() {
        let set = generate_keys_as_str_and_type(4);

        // Go through a full cycle of validators with changing phase at each new view
        let mut vp = ValidatorProcess::new(set.0[0].clone(), set.0.clone());
        assert_eq!(set.0[0], vp.primary());
        assert_eq!(State::new(0), vp.phase());
        assert_eq!(0, vp.view());
        assert_eq!(true, vp.is_normal());
        assert_eq!(true, vp.is_primary());
        vp.inc_v();
        vp.next_primary();
        vp.phase.next();
        assert_eq!(set.0[1], vp.primary());
        assert_eq!(State::new(1), vp.phase());
        assert_eq!(1, vp.view());
        assert_eq!(true, vp.is_normal());
        assert_eq!(false, vp.is_primary());
        vp.inc_v();
        vp.next_primary();
        vp.phase.next();
        assert_eq!(set.0[2], vp.primary());
        assert_eq!(State::new(2), vp.phase());
        assert_eq!(2, vp.view());
        assert_eq!(true, vp.is_normal());
        assert_eq!(false, vp.is_primary());
        vp.inc_v();
        vp.next_primary();
        vp.phase.next();
        assert_eq!(set.0[3], vp.primary());
        assert_eq!(State::new(3), vp.phase());
        assert_eq!(3, vp.view());
        assert_eq!(true, vp.is_normal());
        assert_eq!(false, vp.is_primary());
        vp.inc_v();
        vp.next_primary();
        vp.phase.next();
        assert_eq!(set.0[0], vp.primary());
        assert_eq!(State::new(0), vp.phase());
        assert_eq!(4, vp.view());
        assert_eq!(true, vp.is_normal());
        assert_eq!(true, vp.is_primary());

        // Process interrupted because primary did not respond
        vp.phase.enter_vc();
        assert_eq!(set.0[0], vp.primary());
        assert_eq!(State::new(4), vp.phase());
        vp.phase.next();
        assert_eq!(State::new(5), vp.phase());
        vp.phase.next();
        vp.inc_v();
        assert_eq!(State::new(0), vp.phase());
        assert_eq!(5, vp.view());

        // Verify previous primaries through the view number
        for v in 0..vp.big_n() {
            // primaries are chosen according to index at v % N
            assert_eq!(vp.set()[v], vp.get_primary_at_view(v as u64));
        }
    }

    #[test]
    #[should_panic]
    fn less_than_three_other_validators() {
        let vals = generate_keys_as_str_and_type(2);
        let local_id = vals.0[0].clone();
        ValidatorProcess::new(local_id, vals.0);
    }
}
