use super::block::Block;
use super::transaction::Transaction;
use std::sync::mpsc::{Receiver, Sender};

/// PoolManager manages the inbound and outbound messages which changes the state
/// of the transaction pool. The outbound communication is conducted through the
/// underlying p2p network. The roles of the pool manager are as following:
///   1) communicate with the underlying p2p network and include transactions
///      into the unconfirmed tx pool; and
///   2) mark confirmed transactions as ready to be broadcast (after having reached a
///      consensus) which means that they are moved into the pending tx pool; and
///   3) broadcast pending transactions to its peers
struct PoolManager {
    // last_updated is the last time (in UTC milliseconds) in which the pool manager
    // heard from either the p2p network or from its internal consensus engine in
    // regards to the latest gossip about a new block or its latest update on any
    // finalized (committed) blocks
    last_updated: i64,

    // rx is a receive channel which listens to p2p messages with proposed blocks.
    // These are unwrapped into transactions when delivered to the tx pool.
    rx: Receiver<Block>,

    // tx is a sender channel which transmits unconfirmed and pending transactions
    // to the local and shared tx pool, respectively
    tx: Sender<Transaction>,
}

#[cfg(test)]
mod tests {

    // tests external p2p messages (network layer) that are inbound
    #[test]
    fn test_receive_blocks_and_deliver_unconfirmed_txs_to_pool() {
        assert_eq!(true, false);
    }

    // tests internal worker messages (consensus layer)
    #[test]
    fn test_deliver_confirmed_blocks_as_txs_to_pool() {
        assert_eq!(true, false);
    }

    // tests both external and internal messages
    #[test]
    fn test_deliver_high_amount_of_concurrent_messages_to_pool() {
        assert_eq!(true, false);
    }
}
