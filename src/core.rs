use crate::block::Block;
use crate::state_db::KeyValueIO;
use crate::state_db::StateDB;
use crate::txn_pool::create_new_tx_pool;
use crate::txn_pool::TxPool;

extern crate crypto;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

use std::cell::RefCell;
use std::rc::Rc;

#[allow(dead_code)]
pub struct Blockchain {
    chain: std::vec::Vec<Block>,
    pool: TxPool,
    account_db: StateDB,
}

impl Blockchain {
    #[allow(dead_code)]
    pub fn new(account_db_path: &str) -> Self {
        // we enable a shared ownership of hash_out ..
        let hash_out = Rc::new(RefCell::new(create_hash()));
        // and allow `ss` to perform runtime borrow checking ..
        let ss = hash_out.clone();
        // to use this dummy hash in the first block
        let block = Block::new(
            ss.borrow().to_string(),
            ss.borrow().to_string(),
            0,
            0,
            "InitBlock",
        );
        let mut chain_of_blocks = std::vec::Vec::<Block>::new();
        chain_of_blocks.push(block);
        Self {
            chain: chain_of_blocks,
            pool: create_new_tx_pool("0x", true),
            account_db: StateDB::new(account_db_path),
        }
    }
}

fn create_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.input(b"0x123");
    let hash_out = hasher.result_str();
    hash_out
}
