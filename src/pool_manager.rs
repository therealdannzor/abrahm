use super::block::Block;
use crate::swiss_knife::helper;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Mutex};
use std::thread;

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
    last_updated: Mutex<i64>,

    // rx is a receive channel which listens to p2p messages with proposed blocks.
    // These are unwrapped into transactions when delivered to the tx pool.
    rx: Receiver<Block>,

    // tx is a sender channel which transmits unconfirmed and pending transactions
    // to the local and shared tx pool, respectively
    tx: Sender<Block>,
}

#[allow(dead_code)]
impl PoolManager {
    pub fn new() -> Self {
        let (tx, rx): (Sender<Block>, Receiver<Block>) = mpsc::channel();
        Self {
            last_updated: Mutex::new(helper::new_timestamp()),
            rx,
            tx,
        }
    }

    pub fn last_time(&self) -> i64 {
        *self.last_updated.lock().unwrap()
    }

    pub fn get_new_block(&self) -> Block {
        // update timestamp of the latest try to fetch a block
        {
            update_mutex_timestamp(&self.last_updated);
        }

        // use the non-blocking and optimistic check to fetch
        let rec = self.rx.try_recv();
        let block: Block;
        match rec {
            Ok(b) => block = b,
            Err(_) => panic!("error when fetching block"),
        }

        block
    }

    pub fn send_block(&self, b: Block) {
        {
            update_mutex_timestamp(&self.last_updated);
        }

        // copy the tx endpoint
        let thread_tx = self.tx.clone();

        // use standard threads (not the same as lightweight green threads)
        let child = thread::spawn(move || {
            thread_tx.send(b).unwrap();
        });

        // wait for work to complete
        child.join().expect("error: child thread panicked");
    }
}

fn update_mutex_timestamp(m: &Mutex<i64>) {
    let mut t = m.lock().unwrap();
    *t = helper::new_timestamp();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;

    fn setup() -> (Vec<Block>, PoolManager) {
        // instead of intializing the whole tx pool struct together with
        // all its sub components, we abstract it as a vector of blocks to
        // focus on the channel functionalities (which is the system under
        // test in this case)
        let pool = Vec::<Block>::new();
        let manager = PoolManager::new();
        (pool, manager)
    }

    fn generate_x_blocks(x: u8) -> Vec<Block> {
        let mut res = Vec::<Block>::new();
        for i in 1..x + 1 {
            let b = Block::new(
                i.to_string(),
                (i - 1).to_string(),
                helper::new_timestamp(),
                "data",
            );
            res.push(b);
        }
        res
    }

    // mocks inbound messages and tests the send & receive channels [pool manager task #1 and #2]
    #[test]
    fn receives_blocks_and_delivers_to_pool() {
        let (_, manager) = setup();
        let blocks_to_send = generate_x_blocks(3);
        let amount_blocks = blocks_to_send.len();
        let mut responses = Vec::<Block>::new();

        for i in 0..amount_blocks {
            manager.send_block(blocks_to_send[i].clone());
        }

        for _ in 0..amount_blocks {
            let block = manager.get_new_block();
            responses.push(block);
        }

        let b1 = responses[0].clone();
        let b2 = responses[1].clone();
        let b3 = responses[2].clone();
        assert_eq!(b1.hash(), blocks_to_send[0].hash());
        assert_eq!(b1.previous_hash(), blocks_to_send[0].previous_hash());
        assert_eq!(b2.hash(), blocks_to_send[1].hash());
        assert_eq!(b2.previous_hash(), blocks_to_send[1].previous_hash());
        assert_eq!(b3.hash(), blocks_to_send[2].hash());
        assert_eq!(b3.previous_hash(), blocks_to_send[2].previous_hash());
    }

    // tests that outbound external messages are received properly [pool manager task #3]
    #[test]
    fn broadcasts_confirmed_txs_as_blocks_to_other_peers() {
        assert_eq!(true, false);
    }
}
