#![allow(unused)]

use crate::consensus::{common::ValidatorSet, core::ConsensusChain, engine::Engine};
use crate::ledger::bootstrap::BootStrap;
use crate::ledger::state_db::{KeyValueIO, StateDB};
use crate::network::api::{spawn_network_io_listeners, spawn_peer_discovery_listener};
use crate::network::client_handle::MessagePeerHandle;
use crate::network::mdns::ValidatedPeer;
use crate::types::{block::Block, pool::TxPool};
use std::vec::Vec;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::mpsc::{self, Receiver};

pub struct Blockchain {
    // contiguous link of blocks
    chain: Vec<Block>,

    // memory pool of transactions
    pool: TxPool,

    // account states
    account_db: StateDB,

    // kickstart keys and connect permissioned peers
    bootstrap: BootStrap,

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
        stream_cap: usize,
        validators: Option<Vec<String>>,
        blockchain_channel: mpsc::Sender<Block>,
    ) -> Self {
        let mut bootstrap = BootStrap::new();
        if validators.is_none() {
            bootstrap.setup(None);
        } else {
            bootstrap.setup(validators);
        }

        let genesis_block = Block::genesis("0x");
        let db_path = "/database";
        let pub_key_hex = bootstrap.get_public_hex();
        let pub_key_type = bootstrap.get_public_as_type();
        let validator_peers = bootstrap.get_peers_str();

        Self {
            chain: vec![genesis_block.clone()],
            pool: TxPool::new(),
            account_db: account_db_setup(db_path),
            bootstrap,
            consensus: ConsensusChain::new(
                Engine::new(pub_key_hex.clone(), validator_peers),
                genesis_block,
                pub_key_type.clone(), // local id
                pub_key_type,         // set local id as initial proposer
                blockchain_channel,
            ),
        }
    }

    pub async fn id_and_peer_setup(&mut self) -> (MessagePeerHandle, Receiver<ValidatedPeer>) {
        let second = std::time::Duration::from_secs(1);

        let validator_peers = self.bootstrap.get_peers_str();
        let (message_peer_handle, join_server, join_peer, join_inbox) =
            spawn_network_io_listeners(validator_peers.clone()).await;

        std::thread::sleep(2 * second);
        let port_serv = message_peer_handle.get_host_port().await;
        std::thread::sleep(second);

        let (recv_peer_discv, join_discv) = spawn_peer_discovery_listener(
            self.bootstrap.get_public_as_type(),
            self.bootstrap.get_secret_as_type(),
            port_serv,
            validator_peers,
        )
        .await;

        join_server.await.unwrap();
        join_peer.await.unwrap();
        join_inbox.await.unwrap();
        join_discv.await.unwrap();

        (message_peer_handle, recv_peer_discv)
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
    use crate::consensus::testcommons::generate_keys_as_str;
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
        let keys = generate_keys_as_str(4);
        let (sk, pk) = themis::keygen::gen_ec_key_pair().split();
        let (send, recv): (mpsc::Sender<Block>, mpsc::Receiver<Block>) = mpsc::channel(4);
        let mut bc = Blockchain::new(10, Some(keys), send);

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

        let mut _rmdir = std::fs::remove_dir_all("/test");
        let _rmdir = std::fs::remove_dir_all("/database");
    }
}
