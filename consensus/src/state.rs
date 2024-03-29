#![allow(unused)]

use super::common::{SequenceNumber, View};
use std::cmp::PartialEq;
use std::ops::Deref;

#[derive(Clone, Debug)]
// Phase messages
pub struct State(u8);
impl State {
    pub fn init() -> Self {
        Self(0)
    }

    // Valid values:
    // 0 = ACCEPT REQUESTS
    // 1 = PREPREPARE
    // 2 = PREPARE
    // 3 = COMMIT
    // 4 = VIEW CHANGE
    // 5 = NEW VIEW
    // 6 = CHECKPOINT
    pub fn new(num: u8) -> Self {
        if num < 7 {
            Self(num)
        } else {
            panic!("cannot create invalid state");
        }
    }

    pub fn into_inner(self) -> u8 {
        self.0
    }

    // Start the view change process
    pub fn enter_vc(&mut self) {
        self.0 = 4;
    }

    pub fn enter_cp(&mut self) {
        self.0 = 6;
    }

    // Advance to the next stage of a state
    pub fn next(&mut self) {
        match self.0 {
            // Normal case operations is:
            // ACCEPT REQ -> PREPREPARE -> PREPARE -> COMMIT -> ACCEPT REQ ..
            //
            // View change process is when the normal case is interrupted:
            // ACCEPT REQ / PREPREPARE / PREPARE / COMMIT -> VIEW CHANGE ->
            // NEW-VIEW -> ACCEPT REQ ..
            //
            // The checkpoint state happens periodically as the process progresses.
            // COMMIT -> CHECKPOINT -> ACCEPT REQ ...
            0 => self.0 = 1,
            1 => self.0 = 2,
            2 => self.0 = 3,
            3 => self.0 = 0,
            4 => self.0 = 5,
            5 => self.0 = 0,
            6 => self.0 = 0,
            _ => panic!("this should never happen"),
        }
    }
}
impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Represents the format of all the consensus messages between peers
#[derive(Clone, Debug)]
pub struct M {
    // denotes the type of the message
    pub phase: State,
    // identity of the replica
    pub i: String,
    // provides liveness by allowing changes if (when) primary fails
    pub v: View,
    // order requests with consecutive sequence numbers for each replica
    pub n: SequenceNumber,
    // message digest
    pub d: String,
}

impl M {
    pub fn new(phase: State, i: String, v: View, n: SequenceNumber, d: String) -> Self {
        Self {
            phase: phase.clone(),
            i: i.clone(),
            v,
            n,
            d,
        }
    }

    pub fn init(
        self,
        i: String,
        digest_fn: fn(phase: State, i: String, v: View, n: SequenceNumber) -> String,
    ) -> Self {
        Self {
            phase: State::init(),
            i: i.clone(),
            v: 0,
            n: 0,
            d: digest_fn(self.phase, i, 0, 0),
        }
    }

    fn mut_phase(mut self, phase: State) {
        self.phase = phase;
    }

    fn next_phase(mut self) {
        let curr = self.phase.into_inner();
        match curr {
            0 => self.phase = State::new(1), // proceed to PREPREPARE
            1 => self.phase = State::new(2), // proceed to PREPARE
            2 => self.phase = State::new(3), // proceed to COMMIT
            3 => self.phase = State::new(0), // proceed to ACCEPT REQUESTS
            _ => log::debug!("no next phase: given phase not part of 3-phase-consensus"),
        }
    }
}

impl Deref for M {
    type Target = u64; // View

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl PartialEq for M {
    // Two messages are equal if they are in the same view, have the same sequence number,
    // and the same message digest. The identities and phase message type may vary.
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v && self.n == other.n && self.d == other.d
    }
}
