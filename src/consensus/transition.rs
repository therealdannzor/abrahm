extern crate crypto;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
// Transition represents the state transition from a current and established state S0, to a future
// not-yet-confirmed state S1. Confirmed in this sense is represented by a consensus vote in favor
// of it.
//
// As part of the transition process, each client runs the necessary internal checks first
// (e.g. no double spending or other invalid operations) before finalizing a Transition struct to
// be shared externally. The only valid operation we initially support is value transactions.
//
// To transition from one state to another is a representation of change: an ordered and sequential
// set of operations and not a function of time. Instead, this is managed by higher layer abstractions
// where it needs to be exposed to external agents (i.e. peers).
//
// For the initial version, the transition has two parts:
// (1) existing state of account balances (proved by the current root hash); and
// (2) further transactions proposed to be applied to the current stable state
pub struct Transition {
    // current state as a hash (S0)
    from_root_hash: String,
    // the operations which translates to the next state
    txs: std::vec::Vec<Transact>,
    // the new state hash after operations are applied (S1)
    to_root_hash: String,
}

// next_state calculates the next root hash to be used after the transition is processed.
// It uses the same principle as the state db root hash, by using sender/sendee information.
// Not the most safe approach since it can be deterministically predicted based on input, and
// hardening that is a next step after having a complete e2e POC.
fn next_state(txs: std::vec::Vec<Transact>, curr_root_hash: &str) -> String {
    let mut input = curr_root_hash.to_string();
    for tx in txs.iter() {
        input.push_str(&tx.serialize());
    }
    let mut hash_out = Sha256::new();
    hash_out.input_str(&input);

    hash_out.result_str()
}

impl Transition {
    pub fn new(hash: String, txs: std::vec::Vec<Transact>) -> Self {
        if hash == "" {
            panic!("cannot have an empty existing root hash");
        }

        let next_state = next_state(txs.clone(), &hash);

        Self {
            from_root_hash: hash.to_string(),
            txs,
            to_root_hash: next_state,
        }
    }

    pub fn digest(&self) -> String {
        let mut hash_out = Sha256::new();
        let mut res = self.to_root_hash.clone();
        res.push_str(&self.from_root_hash.clone());
        hash_out.input_str(&res);
        hash_out.result_str()
    }
}

// Transact is the internal representation of a transaction between accounts. Note that its purpose
// is to make sure that a transaction is *possible* from a spending perspective (i.e. it's not
// overspending a balance). It does not worry about the actual execution.
//
// In contrast, an external transaction is handled in conjunction with including it to a mempool.
// Hence, we only require checks that relates to the state db in this transaction.
#[derive(Serialize, Deserialize, Clone)]
pub struct Transact {
    // sender
    from: u8,
    // recipient
    to: u8,
    // amount to send
    amount: u32,
}

impl Transact {
    pub fn new(from: u8, to: u8, amount: u32) -> Self {
        if amount < 1 {
            panic!("non-valid amount in a transaction");
        }

        Transact { from, to, amount }
    }

    pub fn from(&self) -> u8 {
        self.from.clone()
    }

    pub fn to(&self) -> u8 {
        self.to.clone()
    }

    pub fn amount(&self) -> u32 {
        self.amount.clone()
    }

    // pack all components and hash
    pub fn serialize(&self) -> String {
        let mut res = "".to_string();
        res.insert_str(0, &self.from().to_string());
        res.insert_str(0, &self.to().to_string());

        let mut hash_out = Sha256::new();
        hash_out.input_str(&res);
        hash_out.result_str()
    }
}
