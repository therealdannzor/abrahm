#![allow(unused)]
use crypto::{digest::Digest, sha2::Sha256};

use super::transition::Transition;
use crate::swiss_knife::helper;

// Request corresponds to a proposal of a state machine operation, sent by the primary.
//
// Since there is no central client in our (theoretical) decentralized network, this execution
// request of an operation must be broadcast to all peers who belongs to the committee set.
pub struct Request {
    // the current timestamp to ensure exactly-once semantics
    timestamp: i64,

    // the work which this operation is to execute
    next_state: Transition,

    // the proposer
    origin_id: String,
}

impl Request {
    pub fn new(next_state: Transition, id: &str) -> Self {
        Self {
            timestamp: helper::new_timestamp(),
            next_state,
            origin_id: id.to_string(),
        }
    }

    pub fn timestamp(&self) -> String {
        self.timestamp.to_string()
    }

    pub fn from(&self) -> String {
        self.origin_id.clone()
    }

    pub fn digest(&self) -> String {
        let mut hash_out = Sha256::new();
        let ts = self.timestamp.to_string();
        let transit = self.next_state.digest();
        hash_out.input_str(&ts);
        hash_out.input_str(&transit);
        hash_out.result_str()
    }
}
