#![allow(unused)]

use super::common::{Committer, ValidatorSet, View};
use std::vec::Vec;

// ValidatorEngine assigns and and manages the primary (leader) in the replication process.
// Sometimes this replica will be the leader/primary but it is not a guarantee. The engine
// participates in making sure that all replicas agree on the same leader at the same time.
//
// In PBFT, the leader is replaced to make sure the system can guarantee liveness. But only if
// the system is not progressing and comes to a decision to execute a certain request within time.
// This approach can be called to have a "sticky leader" as opposed to changing the elected leader
// periodically in a consistent manner.
pub struct ValidatorEngine {
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
    // be a discrepancy in choice of leaders.
    set: Vec<&'static str>,

    // When this flag is enabled, the replica is in the normal operational mode with receiving and
    // sending messages as part of the three phase consensus. If this flag is disabled (false),
    // that means that its timer has expired and that it cannot proceed. Consequently, it its no
    // longer in normal mode and desires to start negotiating a view change with the other
    // replicas.
    normal_mode: bool,
}

impl ValidatorEngine {
    pub fn new(set: Vec<&'static str>) -> Self {
        Self {
            view: 0,
            primary: set[0].to_string(),
            set,
            normal_mode: true,
        }
    }
}
