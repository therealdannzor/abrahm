use super::common::{
    extract_discv_port_field, extract_server_port_field, public_key_and_payload_to_vec,
    verify_p2p_message,
};
use libp2p::{
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use rand::{
    distributions::{Distribution, Uniform},
    thread_rng,
};
use std::error::Error;
use swiss_knife::helper::hash_and_sign_message_digest;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc::Sender, Notify};
use tokio::task::JoinHandle;

pub async fn spawn_peer_discovery_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    serv_port: String,
    tx: Sender<ValidatedPeer>,
    kill: Sender<bool>,
    to_discover: Vec<String>,
) -> JoinHandle<()> {
    let join = tokio::spawn(async move {
        match peer_discovery_loop(pk, sk, serv_port, tx, kill, to_discover).await {
            Ok(()) => {}
            Err(e) => {
                panic!("discovery loop failed: {:?}", e);
            }
        };
    });

    join
}

async fn peer_discovery_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    serv_port: String,
    tx: Sender<ValidatedPeer>,
    kill: Sender<bool>,
    to_discover: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let keys_id = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys_id.public());
    let transport = libp2p::development_transport(keys_id).await?;
    let behaviour = Mdns::new(MdnsConfig::default()).await?;

    let mut swarm = Swarm::new(transport, behaviour, peer_id);
    let assign_multi_addr = "/ip4/0.0.0.0/tcp/0".parse::<libp2p::Multiaddr>()?;
    let _ = swarm.listen_on(assign_multi_addr.clone());
    let mut my_disc_port = "".to_string();

    loop {
        let tx = tx.clone();
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(MdnsEvent::Discovered(peers)) => {
                for (_, addr) in peers {
                    let discv_addr = multi_to_socket_addr(addr.clone());
                    let socket = UdpSocket::bind("127.0.0.1:0").await?;
                    let broadcast_disc_msg = create_discv_handshake(
                        pk.clone(),
                        sk.clone(),
                        my_disc_port.clone(),
                        serv_port.clone(),
                    );
                    tokio::spawn(async move {
                        // send each new peer three discovery messages at each new discovery event
                        let to_address = discv_addr.clone();
                        let payload = broadcast_disc_msg.clone();
                        let res = socket.send_to(&payload, to_address.clone()).await;
                        if res.is_err() {
                            log::error!("discovery dispatch failed: {:?}", res);
                        }
                    });
                }
            }
            SwarmEvent::NewListenAddr {
                listener_id: _,
                address,
            } => {
                let hostname = multi_to_host_addr(address.clone());
                my_disc_port = extract_port_from_multi(address.clone());

                if hostname == "127.0.0.1" {
                    let socket_addr = multi_to_socket_addr(address);
                    let socket = UdpSocket::bind(&socket_addr).await?;
                    let serv = Server {
                        socket,
                        buf: vec![0; 248],
                        stream_size: None,
                        ready_upgrade_mode: false,
                    };
                    let list_peers = to_discover.clone();
                    log::debug!("start server buffer to receive other discv messages");
                    let kill_tx = kill.clone();
                    tokio::spawn(async move {
                        let _ = serv.run(tx, kill_tx, list_peers).await;
                    });
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedPeer {
    disc_port: String,
    serv_port: String,
    key: EcdsaPublicKey,
}
impl ValidatedPeer {
    fn new(disc_port: Vec<u8>, serv_port: Vec<u8>, public_key: Vec<u8>) -> Self {
        let disc_port = match std::str::from_utf8(&disc_port) {
            Ok(s) => s.to_string(),
            Err(e) => {
                panic!("this should not happen: {}", e);
            }
        };
        let serv_port = match std::str::from_utf8(&serv_port) {
            Ok(s) => s.to_string(),
            Err(e) => {
                panic!("this should not happen: {}", e);
            }
        };
        let key = match EcdsaPublicKey::try_from_slice(public_key) {
            Ok(k) => k,
            Err(e) => {
                panic!("this should not happen: {}", e);
            }
        };
        Self {
            disc_port,
            serv_port,
            key,
        }
    }
    pub fn disc_port(&self) -> String {
        self.disc_port.clone()
    }

    pub fn serv_port(&self) -> String {
        self.serv_port.clone()
    }

    pub fn key(&self) -> EcdsaPublicKey {
        self.key.clone()
    }
}

pub struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    stream_size: Option<usize>,
    ready_upgrade_mode: bool,
}

impl Server {
    async fn run(
        mut self,
        tx: Sender<ValidatedPeer>,
        kill: Sender<bool>,
        to_find: Vec<String>,
    ) -> Result<(), std::io::Error> {
        let total_peers = to_find.len();
        // contains discovered and verified peers (i.e., signed messages from validator set)
        let mut peers_confirmed = Vec::new();
        // contains peers who have successfully found its neighbors (i.e., full validator set)
        let mut peers_ready = Vec::new();
        let wait_time = std::time::Duration::from_secs(2);
        let notif = Notify::new();

        loop {
            if let Some(_) = self.stream_size {
                let start = std::time::Instant::now();

                notif.notified().await;
                let (is_verified, public_key) = verify_p2p_message(self.buf.clone());
                if is_verified {
                    let public_hex = hex::encode(public_key.clone());
                    let msg = self.buf.clone();
                    // to make sure we don't count the same peer more than once
                    if peers_confirmed.contains(&public_hex) && self.ready_upgrade_mode {
                        if check_for_ready_message(msg) {
                            if !peers_ready.contains(&public_hex) {
                                peers_ready.push(public_hex);
                            } else {
                                log::warn!("peer already known to be ready");
                            }
                        } else {
                            log::error!("not a ready message, discard it");
                        }
                        if peers_ready.len() == total_peers {
                            log::info!("all peers are ready, proceed to full connection");
                            break;
                        }
                    } else {
                        let public_key_vec = public_key.as_ref().to_vec();
                        let disc_port = extract_discv_port_field(msg.clone());
                        let serv_port = extract_server_port_field(msg);
                        if !peers_confirmed.contains(&public_hex) {
                            // add peers found for the first time
                            if let Some(_) = to_find.iter().position(|x| *x == public_hex) {
                                peers_confirmed.push(public_hex);
                                log::warn!("found new peer, added to list");
                                if peers_confirmed.len() == total_peers {
                                    log::info!("enter ready-to-upgrade mode");
                                    self.ready_upgrade_mode = true;
                                }
                            }
                            let validated =
                                ValidatedPeer::new(disc_port, serv_port, public_key_vec);

                            let _ = tx.send(validated).await;
                        } else {
                            log::warn!("peer already confirmed");
                        }
                    }
                } else {
                    log::error!("could not authenticate buffered message, discarding");
                }
                let elapsed_time = start.elapsed();
                if let Some(time) = wait_time.checked_sub(elapsed_time) {
                    tokio::time::sleep(time).await;
                }
            }
            self.buf = vec![0; 248];
            self.stream_size = Some(self.socket.recv(&mut self.buf).await?);
            log::debug!("fetch new message from stream");
            notif.notify_one();
            log::debug!(
                "found: {}/{}, ready: {}/{}",
                peers_confirmed.len(),
                total_peers,
                peers_ready.len(),
                total_peers,
            );
        }
        log::info!("discovery completed, exiting");
        // alert api that discovery is finished
        let _ = kill.send(true).await;

        Ok(())
    }
}

fn multi_to_socket_addr(multi_address: libp2p::Multiaddr) -> String {
    let port = extract_port_from_multi(multi_address);
    let mut socket_addr = "127.0.0.1:".to_string();
    socket_addr.push_str(&port);
    socket_addr
}

fn extract_port_from_multi(multi_adress: libp2p::Multiaddr) -> String {
    let multistr = multi_adress.to_string();
    let sep: Vec<&str> = multistr.split("/").collect();
    let last_ind = sep.len() - 1;
    sep[last_ind].to_string()
}

fn multi_to_host_addr(multi_address: libp2p::Multiaddr) -> String {
    let multistr = multi_address.to_string();
    let sep: Vec<&str> = multistr.split("/").collect();
    let host_ind = 2;
    let hostname = sep[host_ind].to_string();
    hostname
}

// create_discv_handshake creates a discovery handshake message containing the:
// * client's public key,
// * a discovery port to finish the discovery protocol;
// * a message port to communicate with the server; and
// * a signature of the hash of these two items.
//
// More formally, a message looks like so
// { PUBLIC_KEY | PORT | H(PUBLIC_KEY | PORT)_C }
// where '|' denotes append and H(x)_C a client C signing a hash of a message {x}
//
fn create_discv_handshake(
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    disc_port: String,
    msg_port: String,
) -> Vec<u8> {
    if disc_port.len() != 5 {
        log::error!("discovery port length is incorrect");
        return vec![0];
    } else if msg_port.len() != 5 {
        log::error!("message port length is incorrect, discv handshake flawed");
        return vec![0];
    } else if !is_string_numeric(disc_port.clone()) {
        log::error!("discovery port is not numeric");
        return vec![0];
    } else if !is_string_numeric(msg_port.clone()) {
        log::error!("message port is not numeric");
        return vec![0];
    }

    let mut result = Vec::new();
    let mut payload = "".to_string();
    payload.push_str(&disc_port);
    payload.push_str(&msg_port);

    // First half is PUBLIC_KEY | PORT (in bytes)
    let first_half = public_key_and_payload_to_vec(public_key, payload);
    // Second half is H(PUBLIC_KEY | PORT)_C (in bytes)
    let second_half = hash_and_sign_message_digest(secret_key, first_half.clone());

    result.extend(first_half);
    result.extend(second_half);

    result
}

const PUB_KEY_LEN: usize = 90;

fn check_for_ready_message(v: Vec<u8>) -> bool {
    let expected = "READYREADY".to_string().as_bytes().to_vec();
    let payload_len = expected.len();
    let p = v[PUB_KEY_LEN..PUB_KEY_LEN + payload_len].to_vec();
    p == expected
}

fn is_string_numeric(s: String) -> bool {
    for c in s.chars() {
        if !c.is_numeric() {
            return false;
        }
    }
    true
}

pub fn create_rnd_number(from: usize, to: usize) -> usize {
    let mut rng = thread_rng();
    Uniform::new_inclusive(from, to).sample(&mut rng)
}
