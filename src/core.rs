use crate::block::Block;
use crate::state_db::KeyValueIO;
use crate::state_db::StateDB;
use crate::txn_pool::create_new_tx_pool;
use crate::txn_pool::TxPool;

use std::vec::Vec;

#[allow(dead_code)]
pub struct Blockchain {
    chain: Vec<Block>,
    pool: TxPool,
    account_db: StateDB,
}

impl Blockchain {
    // new initializes the blockchain which contains the:
    // (1) link of blocks [vector],
    // (2) transaction pool,
    // (3) backend with user balances
    //
    // Parameters
    // `genesis_block`: the first block in the chain
    // `db_path`: the folder where the state db is stored (relative to working tree)
    #[allow(dead_code)]
    pub fn new(genesis_block: Block, db_path: &str) -> Self {
        let mut chain = Vec::<Block>::new();
        chain.push(genesis_block);
        let pool = create_new_tx_pool("0x", true);

        let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        path.push_str(db_path);
        let _crd = std::fs::create_dir(&path);
        let account_db = StateDB::new(&path);

        Self {
            chain,
            pool,
            account_db,
        }
    }

    // append_block appends a block `b` which is assumed to have:
    // (1) a block hash `this_hash`,
    // (2) a local creation timestamp,
    // (3) additional block data.
    // The function then proceeds to link the current latest block's hash
    // to `b` through its field `previous_hash`
    #[allow(dead_code)]
    pub fn append_block(&mut self, mut b: Block) {
        let prev = self.chain.last().unwrap();
        let prev_hash = prev.hash();
        b.set_prev_hash(prev_hash.to_string());
        self.chain.push(b);
    }

    // latest_block peeks at the latest inserted block (the tip) in the chain.
    #[allow(dead_code)]
    pub fn latest_block(&self) -> Block {
        // we can consume the `Some` value received without any need to match/check
        // because the chain will always contains >= 1 block due to the genesis.
        return self.chain.last().unwrap().clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swiss_knife::helper;
    use serial_test::serial;

    macro_rules! hashed {
        ($x:expr) => {
            helper::generate_hash_from_input($x)
        };
    }

    #[test]
    #[serial]
    fn test_block_init_and_insertion() {
        let genesis = Block::genesis("0x");
        let mut bc = Blockchain::new(genesis, "/test");

        let exp_len = 1;
        let exp_hash = hashed!("0x");
        assert_eq!(bc.chain.len(), exp_len);
        assert_eq!(bc.latest_block().hash(), exp_hash);

        let sec_hash = hashed!("0x1");
        let genesis_hash = bc.latest_block().hash().to_string();
        let genesis_time = bc.latest_block().timestamp();
        let sec_block = Block::new(sec_hash, genesis_hash, genesis_time + 1, "blockData");
        bc.append_block(sec_block);

        let exp_len = 2;
        let exp_hash = hashed!("0x1");
        assert_eq!(bc.chain.len(), exp_len);
        assert_eq!(bc.latest_block().hash(), exp_hash);

        let _rmdir = std::fs::remove_dir_all("/test");
    }
}
