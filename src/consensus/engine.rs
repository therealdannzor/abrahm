#![allow(unused)]

use crate::consensus::common::{Committer, View};
use crate::consensus::messages_tp::{Commit, Prepare, Preprepare};
use crate::consensus::request::Request;
use std::collections::HashMap;

// Backlog contains the different messages that each peer accumulates as part of the SMR process
pub struct Backlog {
    request: Request,
    preprepare: Preprepare,
    prepare: Prepare,
    commit: Commit,
}

pub struct Engine {
    // view describes in which view the local client is in
    view: View,

    // messages contains the accumulated set of different messages it has received from other peers
    messages: HashMap<Committer, Backlog>,

    // stable_checkpoint denotes the last point where messages up to this sequence number are
    // finalized, i.e. there is a consensus
    stable_checkpoint: u64,
}
