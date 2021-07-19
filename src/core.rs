#![allow(unused)]

use crate::block::Block;
use crate::consensus::common::ValidatorSet;
use crate::consensus::core::ConsensusChain;
use crate::consensus::engine::Engine;
use crate::ledger::state_db::{KeyValueIO, StateDB};
use crate::network::core::Net;
use crate::txn_pool::TxPool;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};

use std::sync::mpsc;
use std::vec::Vec;

pub struct Blockchain {
    // contiguous link of blocks
    chain: Vec<Block>,

    // memory pool of transactions
    pool: TxPool,

    // account states
    account_db: StateDB,

    // network and message management
    net: Net,

    // consensus backend
    consensus: ConsensusChain,
}

impl Blockchain {
    // new initializes the blockchain which contains the:
    // (1) link of blocks [vector],
    // (2) transaction pool,
    // (3) backend with user balances
    // (4) network manager
    // (5) consensus backend
    //
    // Parameters
    // `genesis_block`: the first block in the chain
    // `db_path`: the folder where the state db is stored (relative to working tree)
    pub fn new(
        genesis_block: Block,
        db_path: &str,
        stream_cap: usize,
        public_key: EcdsaPublicKey,
        secret_key: EcdsaPrivateKey,
        validators: Vec<EcdsaPublicKey>,
        blockchain_channel: mpsc::Sender<Block>,
    ) -> Self {
        Self {
            chain: vec![genesis_block.clone()],
            pool: TxPool::new(),
            account_db: account_db_setup(db_path),
            net: Net::new(stream_cap, public_key.clone(), secret_key),
            consensus: ConsensusChain::new(
                Engine::new(validators[0].clone(), validators.clone()),
                genesis_block,
                public_key,
                validators[0].clone(),
                blockchain_channel,
            ),
        }
    }

    // append_block appends a block `b` which is assumed to have:
    // (1) a block hash `this_hash`,
    // (2) a local creation timestamp,
    // (3) additional block data.
    // The function then proceeds to link the current latest block's hash
    // to `b` through its field `previous_hash`
    pub fn append_block(&mut self, mut b: Block) {
        let prev = self.chain.last().unwrap();
        let prev_hash = prev.hash();
        b.set_prev_hash(prev_hash.to_string());
        self.chain.push(b);
    }

    // latest_block peeks at the latest inserted block (the tip) in the chain.
    pub fn latest_block(&self) -> Block {
        // we can consume the `Some` value received without any need to match/check
        // because the chain will always contains >= 1 block due to the genesis.
        return self.chain.last().unwrap().clone();
    }
}

fn account_db_setup(db_path: &str) -> StateDB {
    let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
    path.push_str(db_path);
    let _crd = std::fs::create_dir(&path);
    StateDB::new(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::testcommons::generate_keys;
    use crate::swiss_knife::helper;
    use serial_test::serial;
    use std::convert::TryFrom;

    macro_rules! hashed {
        ($x:expr) => {
            helper::generate_hash_from_input($x)
        };
    }

    #[test]
    #[serial]
    fn block_init_and_insertion() {
        let keys = generate_keys(4);
        let genesis = Block::genesis("0x");
        let (sk, pk) = themis::keygen::gen_ec_key_pair().split();
        let (send, recv): (mpsc::Sender<Block>, mpsc::Receiver<Block>) = mpsc::channel();
        let mut bc = Blockchain::new(genesis, "/test", 10, pk, sk, keys, send);

        let exp_len = 1;
        let exp_hash = hashed!("0x");
        assert_eq!(bc.chain.len(), exp_len);
        assert_eq!(bc.latest_block().hash(), exp_hash);

        let sec_hash = hashed!("0x1");
        let genesis_hash = bc.latest_block().hash().to_string();
        let genesis_time = bc.latest_block().timestamp();
        let sec_block = Block::new(sec_hash, genesis_hash, genesis_time + 1, "blockData", 0);
        bc.append_block(sec_block);

        let exp_len = 2;
        let exp_hash = hashed!("0x1");
        assert_eq!(bc.chain.len(), exp_len);
        assert_eq!(bc.latest_block().hash(), exp_hash);

        let _rmdir = std::fs::remove_dir_all("/test");
    }
}
