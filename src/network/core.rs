#![allow(unused)]

use super::message::MessageWorker;
use super::node::Node;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};

// Net handles the blockchain network communication.
//
// The message worker: (1) signs and prepares messages to be dispatched, and (2) validates received
// messages.
//
// The node contains the record of TCP connections and handles the different network events.
pub struct Net {
    // Message IO
    pub message_worker: MessageWorker,
    // Node communication IO
    pub node: Node,
}

impl Net {
    pub fn new(
        author: String,
        stream_cap: usize,
        public_key: EcdsaPublicKey,
        secret_key: EcdsaPrivateKey,
    ) -> Self {
        Self {
            message_worker: MessageWorker::new(secret_key, public_key),
            node: Node::new(author, stream_cap),
        }
    }
}
