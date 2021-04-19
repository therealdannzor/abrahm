use crate::block::Block;
use crate::state_db::KeyValueIO;
use crate::state_db::StateDB;
use crate::txn_pool::create_new_tx_pool;
use crate::txn_pool::TxPool;

#[allow(dead_code)]
pub struct Blockchain {
    chain: std::vec::Vec<Block>,
    pool: TxPool,
    account_db: StateDB,
}

impl Blockchain {
    // new initializes the blockchain which contains the:
    // (1) link of blocks [vector],
    // (2) transaction pool,
    // (3) backend with user balances
    #[allow(dead_code)]
    pub fn new(genesis_block: Block, account_db_path: &str) -> Self {
        let mut chain_of_blocks = std::vec::Vec::<Block>::new();
        chain_of_blocks.push(genesis_block);
        Self {
            chain: chain_of_blocks,
            pool: create_new_tx_pool("0x", true),
            account_db: StateDB::new(account_db_path),
        }
    }

    // append_block appends a block `b` which is assumed to have:
    // (1) a block hash `this_hash`,
    // (2) a local creation timestamp,
    // (3) additional block data.
    // The function then proceeds to link the current latest block's hash
    // to `b` through its field `previous_hash`
    #[allow(dead_code)]
    pub fn append_block(&mut self, b: Block) {
        let prev = self.chain.last().copied().unwrap();
        let prev_hash = prev.hash();
        b.set_prev_hash(prev_hash);
        self.chain.push(b);
    }
}
