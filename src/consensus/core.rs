#![allow(unused)]
use super::engine::Engine;
use crate::ledger::state_db::StateDB;
use crate::types::block::Block;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc;

#[derive(Clone)]
// ConsensusChain represents the blockchain replication process to order and finalize state,
// what is considered the 'truth'. We call this continuous activity state negotiation.
//
// The state negotiation process between clients is happening on the consensus protocol level.
// In practice, it includes the coordination of sending, receiving, and processal of messages.
// Based on that, the change of state is then trickled down to other parts of the system such
// as representing changes in account balances through the state database.
pub struct ConsensusChain {
    // Drives the PBFT consensus process and mechanisms
    engine: Engine,

    // Leading block; the last appended block
    head_block: Block,

    // The client identity
    id: EcdsaPublicKey,

    // The client in charge of proposing a state change
    proposer: EcdsaPublicKey,

    // The channel to send updates to the core blockchain
    sender: mpsc::Sender<Block>,
}

impl ConsensusChain {
    pub fn new(
        engine: Engine,
        head_block: Block,
        id: EcdsaPublicKey,
        proposer: EcdsaPublicKey,
        sender: mpsc::Sender<Block>,
    ) -> Self {
        Self {
            engine,
            head_block,
            id,
            proposer,
            sender,
        }
    }

    pub fn switch_proposer(&mut self, new: EcdsaPublicKey) {
        self.proposer = new
    }

    pub fn latest_block(self) -> Block {
        self.head_block
    }

    pub fn engine(self) -> Engine {
        self.engine
    }
}
