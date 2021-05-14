use crate::consensus::common::{SequenceNumber, View};
use crate::consensus::request::Request;

///! Contains the message types for the three-phase consensus (PREPREPARE, PREPARE, COMMIT)

// Preprepare orders requests in the same view despite a faulty primary
pub struct Preprepare {
    v: View,
    n: SequenceNumber,
    d: String, // message digest
}

impl Preprepare {
    pub fn new(r: Request) -> Self {
        Self {
            v: 0,
            n: 0,
            d: r.digest(),
        }
    }
}

// Prepare ensures that preprepare messages (requests) that commit are totally ordered across views
pub struct Prepare {
    v: View,
    n: SequenceNumber,
    d: String, // message digest
    i: u8,     // replica identity
}

impl Prepare {
    pub fn new(v: View, n: SequenceNumber, d: String, i: u8) -> Self {
        Self { v, n, d, i }
    }
}

// Commit finalizes the proposal request and starts the commit phase
pub struct Commit {
    v: View,
    n: SequenceNumber,
    d: String,
    i: u8,
}

impl Commit {
    pub fn new(v: View, n: SequenceNumber, d: String, i: u8) -> Self {
        Self { v, n, d, i }
    }
}
