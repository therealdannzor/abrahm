#![allow(unused)]
use crate::common::{Committer, SequenceNumber, View};
use serde::{Deserialize, Serialize};

///! Contains the message types for the three-phase consensus (PREPREPARE, PREPARE, COMMIT)

#[derive(Serialize, Deserialize, Clone)]
// Preprepare orders requests in the same view despite a faulty primary
pub struct Preprepare {
    v: View,
    n: SequenceNumber,
    d: String, // message digest
    c: Committer,
}

impl Preprepare {
    pub fn new(v: View, n: SequenceNumber, d: String, c: Committer) -> Self {
        Self { v, n, d, c }
    }

    pub fn view(&self) -> View {
        self.v.clone()
    }

    pub fn seq(&self) -> SequenceNumber {
        self.n.clone()
    }

    pub fn digest(&self) -> String {
        self.d.clone()
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

    pub fn view(&self) -> View {
        self.v.clone()
    }

    pub fn seq(&self) -> SequenceNumber {
        self.n.clone()
    }

    pub fn digest(&self) -> String {
        self.d.clone()
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

    pub fn view(&self) -> View {
        self.v.clone()
    }

    pub fn seq(&self) -> SequenceNumber {
        self.n.clone()
    }

    pub fn digest(&self) -> String {
        self.d.clone()
    }
}
