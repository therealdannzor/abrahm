#![allow(unused)]
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use themis::keys::EcdsaPublicKey;

use super::transaction::Transaction;

// IndexedTransaction contains a Transaction with some extra meta data such as the
// sender and the sender's account nonce
#[derive(Clone)]
struct IndexedTransaction {
    // the address is extracted from the Transaction struct
    address: EcdsaPublicKey,

    // the full Transaction struct
    txn: Transaction,

    // the account nonce is being passed on from higher-layer abstractions which keeps count;
    // this field is simply set without any previous knowledge
    account_nonce: u32,
}

// we do not want to compare entire Transaction structs so create a no-op to satisfy BinaryHeap
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
            address: txn.sender(),
            txn,
            account_nonce,
        }
    }
}

// OrderedTransaction is a wrapper of all the transactions that belongs to a unique account,
// sorted by its account nonce in a FIFO manner
struct OrderedTransaction {
    // min_heap contains a min heap of transactions in-flight; in practice a priority queue
    min_heap: BinaryHeap<IndexedTransaction>,

    // priority is equivalent to the account nonce: it starts at 1 and monotonically increases.
    // Note: the lower the number, the higher the priority
    priority: u32,
}

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

    fn pop(&mut self) -> IndexedTransaction {
        //TODO: error / edge case handling
        self.min_heap.pop().unwrap()
    }
}

// TxPool is a local and shared memory pool which validates, orders, and broadcasts transactions.
// Transactions which are confirmed are in a pending hashmap within each account while those
// under the consensus process are treated as unconfirmed. The handler of this struct is the
// pool manager.
pub struct TxPool {
    // pending transactions that are to be processed
    pending: HashMap<EcdsaPublicKey, OrderedTransaction>,
    // unconfirmed transactions that cannot be executed until finalized consensus
    unconfirmed: HashMap<EcdsaPublicKey, OrderedTransaction>,
}

impl TxPool {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            unconfirmed: HashMap::new(),
        }
    }

    // insert a complete ordered transaction store to keep track of pending txs
    fn new_pending_store(&mut self, key: EcdsaPublicKey, val: OrderedTransaction) {
        self.pending.insert(key, val);
    }
    // insert a complete ordered transaction store to keep track of unconfirmed txs
    fn new_unconfirmed_store(&mut self, key: EcdsaPublicKey, val: OrderedTransaction) {
        self.unconfirmed.insert(key, val);
    }
    // insert a pending transaction for a target account
    fn add_pending_tx(&mut self, target: &EcdsaPublicKey, tx: Transaction) {
        if self.pending.contains_key(&target) {
            // circumvent the need to impl trait `IndexMut`
            self.pending.get_mut(&target).unwrap().insert(tx);
        } else {
            self.pending
                .insert(target.clone(), OrderedTransaction::new());
            self.pending.get_mut(&target).unwrap().insert(tx);
        }
    }
    // insert an unconfirmed transaction for a target account
    fn add_unconfirmed_tx(&mut self, target: EcdsaPublicKey, tx: Transaction) {
        if self.unconfirmed.contains_key(&target) {
            self.unconfirmed.get_mut(&target).unwrap().insert(tx);
        }
        //TODO: error handling
    }
    // removes the pending transaction with the highest priority for a target account
    // (same as picking the one with the lowest nonce)
    fn pop_pending_tx(&mut self, target: EcdsaPublicKey) -> IndexedTransaction {
        if self.pending.contains_key(&target) {
            self.pending.get_mut(&target).unwrap().pop()
        } else {
            //TODO: exit with more grace
            panic!("target account missing");
        }
    }

    // if a transaction store for pending txs initialized
    fn empty_pending(&mut self) -> bool {
        return self.pending.is_empty();
    }
    // if a transaction store for unconfirmed txs initialized
    fn empty_unconfirmed(&mut self) -> bool {
        return self.unconfirmed.is_empty();
    }
    // amount of accounts this transaction pool contains (pending txs)
    fn len_pending(&mut self) -> usize {
        return self.pending.len();
    }
    // amount of accounts this transaction pool contains (unconfirmed txs)
    fn len_unconfirmed(&mut self) -> usize {
        return self.unconfirmed.len();
    }
    // amount of transactions a target account has in store (pending txs)
    fn len_target_pending(&self, target: EcdsaPublicKey) -> usize {
        return self.pending.get(&target).unwrap().len();
    }
    // amount of transactions a target account has in store (unconfirmed txs)
    fn len_target_unconfirmed(&mut self, target: EcdsaPublicKey) -> usize {
        return self.unconfirmed[&target].len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::*;
    use themis::keygen;
    use themis::keys::EcdsaPublicKey;

    fn pub_key() -> EcdsaPublicKey {
        let (_, pk) = keygen::gen_ec_key_pair().split();
        pk
    }

    fn new_tx(amount: u32) -> Transaction {
        let alice = pub_key();
        let bob = pub_key();
        Transaction::new(
            alice.clone(), // from
            bob,           // to
            amount,
            "xyz",
            1,
        )
    }

    fn ord_tx_setup() -> OrderedTransaction {
        let mut ord_tx = OrderedTransaction::new();
        ord_tx.insert(new_tx(1));
        assert_eq!(ord_tx.len(), 1);
        assert_eq!(ord_tx.priority, 1);
        ord_tx
    }

    fn pool_setup() -> (TxPool, EcdsaPublicKey) {
        // empty pool so there are neither uncofirmed nor pending txs
        let mut p = TxPool::new();
        assert!(p.empty_unconfirmed());
        assert!(p.empty_pending());
        let alice = pub_key();

        // there is now one account being tracked in the pool, both the pools
        // and Alice's individual tx counts are 1
        p.new_unconfirmed_store(alice.clone(), ord_tx_setup());
        p.new_pending_store(alice.clone(), ord_tx_setup());
        assert_eq!(p.len_unconfirmed(), 1);
        assert_eq!(p.len_pending(), 1);
        assert_eq!(p.len_target_unconfirmed(alice.clone()), 1);
        assert_eq!(p.len_target_pending(alice.clone()), 1);
        (p, alice)
    }

    #[test]
    fn add_three_pending_and_then_pop() {
        // Create four pending transactions: first during setup and
        // then three consecutive ones. The account nonce should be
        // at 4, as should the amount of (pending) transactions.
        let (mut p, alice) = pool_setup();
        p.add_pending_tx(&alice, new_tx(5));
        p.add_pending_tx(&alice, new_tx(5));
        p.add_pending_tx(&alice, new_tx(5));

        // We have now four pending transactions for Alice. By pop'ing
        // four transactions, the pending pool should be empty..
        assert_eq!(p.len_target_pending(alice.clone()), 4);
        let tx1 = p.pop_pending_tx(alice.clone());
        let tx2 = p.pop_pending_tx(alice.clone());
        let tx3 = p.pop_pending_tx(alice.clone());
        let tx4 = p.pop_pending_tx(alice.clone());
        assert_eq!(p.len_target_pending(alice), 0);

        // We verify we have pulled transactions in the correct order:
        // from 1 to 4. They are stored in the indexed transactions vars idtx_i,
        // i = 1,2,3,4.
        assert_eq!(tx1.account_nonce, 1);
        assert_eq!(tx2.account_nonce, 2);
        assert_eq!(tx3.account_nonce, 3);
        assert_eq!(tx4.account_nonce, 4);
    }

    #[test]
    fn unordered_tx_nonces() {
        let (mut p, alice) = pool_setup();
        let mut ord_tx = ord_tx_setup();
        // Assume account nonce 4 and 6 are rejected for some reason and 1, 2, 3, 5, and 7
        // arrive out of order. It is expected that despite this, they are to be successfully
        // prioritized, starting with nonce 1 and ending with 7.
        ord_tx.min_heap.push(IndexedTransaction::new(new_tx(1), 2));
        ord_tx.min_heap.push(IndexedTransaction::new(new_tx(1), 5));
        ord_tx.min_heap.push(IndexedTransaction::new(new_tx(1), 3));
        ord_tx.min_heap.push(IndexedTransaction::new(new_tx(1), 7));
        p.new_pending_store(alice.clone(), ord_tx);

        // 5 pending txs in total
        assert_eq!(p.len_target_pending(alice.clone()), 5);
        let tx1 = p.pop_pending_tx(alice.clone());
        let tx2 = p.pop_pending_tx(alice.clone());
        let tx3 = p.pop_pending_tx(alice.clone());
        let tx4 = p.pop_pending_tx(alice.clone());
        let tx5 = p.pop_pending_tx(alice.clone());

        // Make sure they get popped in right priority (ascending order)
        assert_eq!(tx1.account_nonce, 1);
        assert_eq!(tx2.account_nonce, 2);
        assert_eq!(tx3.account_nonce, 3);
        assert_eq!(tx4.account_nonce, 5);
        assert_eq!(tx5.account_nonce, 7);
    }
}
