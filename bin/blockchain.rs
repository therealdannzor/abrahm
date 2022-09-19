#![allow(unused)]

use crate::cli::read_args;
use crate::consensus::{core::ConsensusChain, engine::Engine};
use crate::ledger::bootstrap::BootStrap;
use crate::ledger::state_db::{KeyValueIO, StateDB};
use crate::network::api::{spawn_io_listeners, spawn_peer_discovery_listener, Networking};
use crate::network::client_handle::MessagePeerHandle;
use crate::network::common::create_short_message;
use crate::network::discovery::{create_rnd_number, ValidatedPeer};
use crate::network::utils::any_udp_socket;
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
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    peers: Vec<String>,
    root_hash: String,
) -> Networking {
    let (backend_port, mut mph, rx_ug) =
        spawn_io_listeners(pk.clone(), sk.clone(), peers.clone(), root_hash.clone()).await;

    let stream_handles =
        spawn_peer_discovery_listener(pk.clone(), sk.clone(), backend_port, peers.clone(), rx_ug)
            .await;

    let mut net = Networking::new();
    net.set_handler(mph);
    net.set_peers(stream_handles);
    log::info!("listener api kickstarted, now listening for events");

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
            let peer_port = peer.port();
            let mut addr = "127.0.0.1:".to_string();
            addr.push_str(&peer_port);
            let my_id_at_peer = peer.short_id();
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
    use crate::consensus::testcommons::generate_keys_as_str_and_type;
    use crate::network::testcommons::{
        create_validator_set_highest_first, peer_credentials, sleep_one_half_second,
        validator_set_as_str,
    };
    use crate::swiss_knife::helper;
    use serial_test::serial;
    use std::convert::TryFrom;
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    macro_rules! hashed {
        ($x:expr) => {
            helper::generate_hash_from_input($x)
        };
    }

    #[test]
    #[serial]
    fn block_init_and_insertion() {
        let (keys, _) = generate_keys_as_str_and_type(4);
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

    #[tokio::test]
    #[serial]
    async fn network_e2e_chain_discovery_upgrade_and_handshake() {
        let mock_pair_peer = peer_credentials();
        let hi_kp = mock_pair_peer.high_keypair;
        let hi_hs = mock_pair_peer.high_handshake;
        let lo_kp = mock_pair_peer.low_keypair;
        let lo_hs = mock_pair_peer.low_handshake;

        let mut kp = create_validator_set_highest_first();
        let (sk1, pk1) = kp[0].clone().split();
        let (sk2, pk2) = kp[1].clone().split();
        let (sk3, pk3) = kp[2].clone().split();
        let (sk4, pk4) = kp[3].clone().split();
        assert_eq!(kp.len(), 4);
        let vals = validator_set_as_str(kp.clone());
        let root_hash = hashed!("0x");

        let (tx, mut rx): (Sender<Networking>, Receiver<Networking>) = mpsc::channel(8);

        let v1 = vals.clone();
        let rh1 = root_hash.clone();
        let tx1 = tx.clone();
        tokio::spawn(async move {
            let n1 = start_listeners(pk1, sk1, v1, rh1).await;
            let _ = tx1.send(n1).await;
        });
        sleep_one_half_second().await;
        let v2 = vals.clone();
        let rh2 = root_hash.clone();
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let n2 = start_listeners(pk2, sk2, v2, rh2.clone()).await;
            let _ = tx2.send(n2).await;
        });
        sleep_one_half_second().await;
        let v3 = vals.clone();
        let rh3 = root_hash.clone();
        let tx3 = tx.clone();
        tokio::spawn(async move {
            let n3 = start_listeners(pk3, sk3, v3, rh3).await;
            let _ = tx3.send(n3).await;
        });
        sleep_one_half_second().await;
        let v4 = vals.clone();
        let rh4 = root_hash.clone();
        let tx4 = tx.clone();
        tokio::spawn(async move {
            let n4 = start_listeners(pk4, sk4, v4, rh4).await;
            let _ = tx4.send(n4).await;
        });

        let mut handlers: Vec<Networking> = Vec::new();
        while let Some(msg) = rx.recv().await {
            handlers.push(msg);
            if handlers.len() == 4 {
                break;
            }
        }

        let h1 = &handlers[0];
        let h2 = &handlers[1];
        let h3 = &handlers[2];
        assert_eq!(h1.get_registered_peers().len(), 3);
        assert_eq!(h2.get_registered_peers().len(), 3);
        assert_eq!(h3.get_registered_peers().len(), 3);
    }
}
