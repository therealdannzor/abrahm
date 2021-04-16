use std::collections::BinaryHeap;
use std::collections::HashMap;

use crate::transaction::Transaction;

// TxSortedMap contains the Transaction objects in a hash map where the key is the current
// local transaction nonce. The nonces are ordered in a binary heap so to always pull the
// most stale transaction to maintain order (FIFO).
#[allow(dead_code)]
struct TxSortedMap {
    txn: HashMap<u64, Transaction>,
    index: BinaryHeap<u64>,
}

impl TxSortedMap {
    fn new() -> Self {
        Self {
            txn: HashMap::<u64, Transaction>::new(),
            index: BinaryHeap::<u64>::new(),
        }
    }
}

// AccTxStore is a wrapper of all the transactions that belongs to a unique account
#[allow(dead_code)]
struct AccTxStore {
    // contiguous flag denotes whether the transactions have to be sequentially ordered
    contiguous: bool,
    // txs contains the sorted hash map of the actual transaction data
    txs: TxSortedMap,
}

#[allow(dead_code)]
impl AccTxStore {
    fn new(contiguous: bool) -> Self {
        Self {
            contiguous,
            txs: TxSortedMap::new(),
        }
    }
}

// TxPool is a memory pool which validates, orders, and broadcasts pending transactions.
#[allow(dead_code)]
pub struct TxPool {
    // pending transactions that are to be processed
    pending: HashMap<&'static str, AccTxStore>,
    // queued transactions that cannot be executed until finalized consensus
    queue: HashMap<&'static str, AccTxStore>,
}

#[allow(dead_code)]
impl TxPool {
    pub fn new() -> Self {
        Self {
            pending: HashMap::<&str, AccTxStore>::new(),
            queue: HashMap::<&str, AccTxStore>::new(),
        }
    }

    fn insert_pending(&mut self, key: &'static str, val: AccTxStore) {
        self.pending.insert(key, val);
    }
    fn insert_queue(&mut self, key: &'static str, val: AccTxStore) {
        self.queue.insert(key, val);
    }
}

// creates a transaction pool (mempool) where `ordered` defines whether the transactions
// have to be processed in sequential order
#[allow(dead_code)]
pub fn create_new_tx_pool(account: &'static str, ordered: bool) -> TxPool {
    let mut pool = TxPool::new();
    let first_store = AccTxStore::new(ordered);
    let second_store = AccTxStore::new(ordered);

    pool.insert_pending(account, first_store);
    pool.insert_queue(account, second_store);
    pool
}
