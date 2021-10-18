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
use tokio::task::JoinHandle;

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
        validators_id: Option<Vec<String>>,
        node_id: Option<String>,
        blockchain_channel: mpsc::Sender<Block>,
    ) -> Self {
        let mut bootstrap = BootStrap::new();
        if validators_id.is_none() {
            bootstrap.setup(None);
        } else {
            bootstrap.setup(validators_id);
        }

        let genesis_block = Block::genesis("0x");
        let pub_key_hex = bootstrap.get_public_hex();
        let pub_key_type = bootstrap.get_public_as_type();
        let validator_peers = bootstrap.get_peers_str();

        Self {
            chain: vec![genesis_block.clone()],
            pool: TxPool::new(),
            account_db: create_db_folder(),
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

    pub fn public_type(&self) -> EcdsaPublicKey {
        self.bootstrap.get_public_as_type()
    }

    pub fn secret_type(&self) -> EcdsaPrivateKey {
        self.bootstrap.get_secret_as_type()
    }

    pub fn peers_str(&self) -> Vec<String> {
        self.bootstrap.get_peers_str()
    }
}

pub async fn id_and_peer_setup(
    validator_peers: Vec<String>,
    public: EcdsaPublicKey,
    secret: EcdsaPrivateKey,
) -> (
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
    MessagePeerHandle,
    Receiver<ValidatedPeer>,
) {
    let second = std::time::Duration::from_secs(1);

    let (message_peer_handle, join_server, join_peer, join_inbox) =
        spawn_network_io_listeners(validator_peers.clone()).await;

    let port_serv = message_peer_handle.get_host_port().await;

    let (recv_peer_discv, join_discv) =
        spawn_peer_discovery_listener(public, secret, port_serv, validator_peers).await;

    (
        join_server,
        join_peer,
        join_inbox,
        join_discv,
        message_peer_handle,
        recv_peer_discv,
    )
}

fn create_db_folder() -> StateDB {
    let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
    path.push_str("/database/client");
    // assumes maximum of 8 (local) validator peers, so 8 different folders
    for i in 0..8 {
        // suppose a potential path for the database
        let mut copy_path = path.clone();
        let digit = std::char::from_digit(i, 10).unwrap();
        copy_path.push(digit);
        // gather metadata anout this potential path
        let _ = match std::fs::metadata(copy_path.clone()) {
            // if it is already occupied (i.e., used by another local peer), skip it
            Ok(x) => continue,
            Err(e) => {
                // set up new state database at available path
                let _ = std::fs::create_dir(&copy_path);
                return StateDB::new(&copy_path);
            }
        };
    }
    panic!("this should not happen");
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
