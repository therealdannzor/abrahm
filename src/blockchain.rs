#![allow(unused)]

use crate::cli::read_args;
use crate::consensus::{core::ConsensusChain, engine::Engine};
use crate::ledger::bootstrap::BootStrap;
use crate::ledger::state_db::{KeyValueIO, StateDB};
use crate::network::api::{spawn_io_listeners, spawn_peer_discovery_listener, Networking};
use crate::network::client_handle::MessagePeerHandle;
use crate::network::common::create_short_message;
use crate::network::discovery::{create_rnd_number, ValidatedPeer};
use crate::network::udp_utils::any_udp_socket;
use crate::network::UpgradedPeerData;
use crate::types::{block::Block, pool::TxPool};
use std::convert::TryInto;
use std::sync::Arc;
use std::vec::Vec;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Notify;

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
        node_id_index: Option<u32>,
        blockchain_channel: mpsc::Sender<Block>,
    ) -> Self {
        let mut index: u32 = 0;
        if node_id_index.is_none() {
            index = read_args();
        } else {
            index = node_id_index.unwrap();
        }
        let mut bootstrap = BootStrap::new(index);
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
            account_db: create_db_folder(index),
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

    pub fn public_hex(&self) -> String {
        self.bootstrap.get_public_hex()
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

    pub fn root_hash(&self) -> String {
        self.account_db.get_root_hash()
    }
}

pub async fn start_listeners(
    mut net: Networking,
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    peers: Vec<String>,
    notify: Arc<Notify>,
) -> Networking {
    let (port, mut mph, rx_ug) = spawn_io_listeners(pk.clone(), sk.clone(), peers.clone()).await;
    log::debug!("server backend port is: {}", port);
    let upgraded_peers =
        spawn_peer_discovery_listener(pk.clone(), sk.clone(), port, peers.clone(), rx_ug).await;

    net.set_handler(mph);
    net.set_peers(upgraded_peers);
    log::info!("listener api kickstarted, now listening for events");

    notify.notify_one();

    net
}

pub async fn broadcast_root_hash(root_hash: String, net: Networking, secret: EcdsaPrivateKey) {
    log::info!("start broadcast root hash");

    let mut message = "RTHASH".to_string();
    message.push_str(&root_hash);
    let ug_peers = net.get_registered_peers();
    let socket = any_udp_socket().await;

    for _ in 0..6 {
        for peer in ug_peers.iter() {
            let peer_port = peer.server_port();
            let mut addr = "127.0.0.1:".to_string();
            addr.push_str(&peer_port);
            let my_id_at_peer = peer.id();
            let payload = create_short_message(my_id_at_peer, secret.clone(), &message);

            let resp_address = addr.clone();
            let p = payload.clone();
            let random_num = create_rnd_number(3, 6).try_into().unwrap();
            // sleep some random time between to not overflow the network
            let dur = tokio::time::Duration::from_secs(random_num);
            tokio::time::sleep(dur).await;

            let _ = socket.send_to(&p, resp_address).await;
        }
    }
}

fn create_db_folder(node_id_index: u32) -> StateDB {
    let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
    path.push_str("/database/client");
    // assumes maximum of 8 (local) validator peers, so 8 different folders
    for i in 0..4 {
        // suppose a potential path for the database
        let mut copy_path = path.clone();
        let digit = std::char::from_digit(i, 10).unwrap();
        copy_path.push(digit);
        // gather metadata anout this potential path
        let _ = match std::fs::metadata(copy_path.clone()) {
            // if it is already occupied (i.e., used by another local peer), skip it
            Ok(_) => continue,
            Err(_) => {
                // set up new state database at available path
                let _ = std::fs::create_dir(&copy_path);
            }
        };
    }
    let node_id = std::char::from_digit(node_id_index, 10).unwrap();
    path.push(node_id);
    return StateDB::new(&path);
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
        let mut bc = Blockchain::new(10, Some(keys), Some(0), send);

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
