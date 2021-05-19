#![allow(unused)]
use super::engine::Engine;
use crate::core::Blockchain;
use crate::state_db::StateDB;

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

    // The client identity
    id: String,

    // The client in charge of proposing a state change
    proposer: String,
}
