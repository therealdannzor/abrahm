use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;

use crate::transaction::Transaction;

// IndexedTransaction contains a Transaction with some extra meta data such as the
// sender and the sender's account nonce
#[allow(dead_code)]
#[derive(Clone)]
struct IndexedTransaction {
    // the address is extracted from the Transaction object
    address: String,

    // the full Transaction object
    txn: Transaction,

    // the account nonce is being passed on from higher-layer abstractions which keeps count;
    // this field is simply set without any previous knowledge
    account_nonce: u32,
}

// we do not want to compare entire Transaction objects so create a no-op to satisfy BinaryHeap
impl Eq for IndexedTransaction {}

// our primary way of comparisons in the priority queue will be through account nonces
impl Ord for IndexedTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        // we make a bold assumption that there will never be a tie
        // between comparisons since a local account's nonces *should*
        // should never reoccur (which is fine in this prototype version)
        other.account_nonce.cmp(&self.account_nonce)
        // .then_with(|| <some other comparison criteria> )
    }
}

// another necessary for the BinaryHeap
impl PartialOrd for IndexedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// last one for the BinaryHeap
impl PartialEq for IndexedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.txn.hash() == other.txn.hash()
    }
}

impl IndexedTransaction {
    fn new(txn: Transaction, account_nonce: u32) -> Self {
        Self {
            address: txn.sender().to_string(),
            txn,
            account_nonce,
        }
    }
}

// OrderedTransaction is a wrapper of all the transactions that belongs to a unique account,
// sorted by its account nonce in a FIFO manner
#[allow(dead_code)]
struct OrderedTransaction {
    // min_heap contains a min heap of transactions in-flight; in practice a priority queue
    min_heap: BinaryHeap<IndexedTransaction>,

    // priority is equivalent to the account nonce: it starts at 1 and monotonically increases.
    // Note: the lower the number, the higher the priority
    priority: u32,
}

#[allow(dead_code)]
impl OrderedTransaction {
    fn new() -> Self {
        Self {
            min_heap: BinaryHeap::<IndexedTransaction>::new(),
            priority: 0,
        }
    }

    fn insert(&mut self, txn: Transaction) {
        // `self.priority` is the min heap's internal state of the account nonces
        self.priority += 1;

        let idtx = IndexedTransaction::new(txn, self.priority);
        self.min_heap.push(idtx);
    }

    fn len(&self) -> usize {
        self.min_heap.len()
    }

    fn is_empty(&self) -> bool {
        self.min_heap.is_empty()
    }
}

// TxPool is a memory pool which validates, orders, and broadcasts pending transactions.
#[allow(dead_code)]
pub struct TxPool {
    // pending transactions that are to be processed
    pending: HashMap<&'static str, OrderedTransaction>,
    // unconfirmed transactions that cannot be executed until finalized consensus
    unconfirmed: HashMap<&'static str, OrderedTransaction>,
}

#[allow(dead_code)]
impl TxPool {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            unconfirmed: HashMap::new(),
        }
    }

    fn insert_pending(&mut self, key: &'static str, val: OrderedTransaction) {
        self.pending.insert(key, val);
    }
    fn insert_unconfirmed(&mut self, key: &'static str, val: OrderedTransaction) {
        self.unconfirmed.insert(key, val);
    }
    fn empty_pending(&mut self) -> bool {
        return self.pending.is_empty();
    }
    fn empty_unconfirmed(&mut self) -> bool {
        return self.unconfirmed.is_empty();
    }
    fn len_pending(&mut self) -> usize {
        return self.pending.len();
    }
    fn len_unconfirmed(&mut self) -> usize {
        return self.unconfirmed.len();
    }
}
