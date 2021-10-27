use super::common::cmp_message_with_signed_digest;
use crate::network::common::public_key_and_port_to_vec;
use crate::swiss_knife::helper::hash_and_sign_message_digest;
use futures::StreamExt;
use libp2p::{
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use std::error::Error;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

pub async fn spawn_peer_discovery_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    serv_port: String,
    tx: Sender<ValidatedPeer>,
    to_discover: Vec<String>,
) -> JoinHandle<()> {
    let join = tokio::spawn(async move {
        match peer_discovery_loop(pk, sk, serv_port, tx, to_discover).await {
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
    to_discover: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let keys_id = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys_id.public());
    let transport = libp2p::development_transport(keys_id).await?;
    let behaviour = Mdns::new(MdnsConfig::default()).await?;

    let mut swarm = Swarm::new(transport, behaviour, peer_id);
    let assign_multi_addr = "/ip4/0.0.0.0/tcp/0".parse::<libp2p::Multiaddr>()?;
    let _ = swarm.listen_on(assign_multi_addr.clone());

    loop {
        let tx = tx.clone();
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(MdnsEvent::Discovered(peers)) => {
                for (_, addr) in peers {
                    let recipient_addr = multi_to_socket_addr(addr);
                    let socket = UdpSocket::bind("127.0.0.1:0").await?;
                    let broadcast_disc_msg =
                        create_discv_handshake(pk.clone(), sk.clone(), serv_port.clone());
                    tokio::spawn(async move {
                        for _ in 0..9 {
                            let to_address = recipient_addr.clone();
                            let payload = broadcast_disc_msg.clone();
                            let three_sec = std::time::Duration::from_secs(3);
                            std::thread::sleep(three_sec);
                            let _ = socket.send_to(&payload, to_address).await;
                        }
                    });
                }
            }
            SwarmEvent::NewListenAddr {
                listener_id: _,
                address,
            } => {
                let hostname = multi_to_host_addr(address.clone());
                if hostname == "127.0.0.1" {
                    let socket_addr = multi_to_socket_addr(address);
                    let socket = UdpSocket::bind(&socket_addr).await?;
                    let serv = Server {
                        socket,
                        buf: vec![0; 243],
                        stream_size: None,
                    };
                    let list_peers = to_discover.clone();
                    tokio::spawn(async move {
                        let _ = serv.run(tx, list_peers).await;
                    });
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
pub struct ValidatedPeer {
    port: Vec<u8>,
    public_key: Vec<u8>,
}

pub struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    stream_size: Option<usize>,
}

impl Server {
    async fn run(
        self,
        tx: Sender<ValidatedPeer>,
        to_find: Vec<String>,
    ) -> Result<(), std::io::Error> {
        let Server {
            socket,
            mut buf,
            mut stream_size,
        } = self;

        let mut peers = to_find.clone();
        let wait_time = std::time::Duration::from_secs(2);
        let notif = tokio::sync::Notify::new();

        loop {
            if let Some(_) = stream_size {
                let start = std::time::Instant::now();

                notif.notified().await;
                let (is_verified, public_key) = verify_discv_handshake(buf.clone());
                if is_verified {
                    log::info!("handshake verified!");
                    let public_hex = hex::encode(public_key.clone());
                    let public_key_vec = public_key.as_ref().to_vec();
                    let port = extract_port_addr_field(buf.clone());
                    if peers.contains(&public_hex) {
                        // remove the peer already found in vector
                        if let Some(pos) = peers.iter().position(|x| *x == public_hex) {
                            // to make sure we don't count the same peer more than once
                            peers.remove(pos);
                            // if we have found all peers we are looking for, bail out
                            if peers.len() == 0 {
                                return Ok(());
                            }
                        }
                        let validated = ValidatedPeer {
                            port,
                            public_key: public_key_vec,
                        };
                        let _ = tx.send(validated).await;
                    } else {
                        log::info!("unknown peer");
                    }
                } else {
                    log::info!("peer verification failed");
                }
                let elapsed_time = start.elapsed();
                if let Some(time) = wait_time.checked_sub(elapsed_time) {
                    tokio::time::sleep(time).await;
                }
            }
            buf.clear();
            buf = vec![0; 243];
            stream_size = Some(socket.recv(&mut buf).await?);
            notif.notify_one();
        }
        Ok(())
    }
}

fn multi_to_socket_addr(multi_address: libp2p::Multiaddr) -> String {
    let multistr = multi_address.to_string();
    let sep: Vec<&str> = multistr.split("/").collect();
    let last_ind = sep.len() - 1;
    let port = sep[last_ind].to_string();
    let mut socket_addr = "127.0.0.1:".to_string();
    socket_addr.push_str(&port);
    socket_addr
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
// * port to communicate with the server; and
// * a signature of the hash of these two items.
//
// More formally, a message looks like so
// { PUBLIC_KEY | PORT | H(PUBLIC_KEY | PORT)_C }
// where '|' denotes append and H(x)_C a client C signing a hash of a message {x}
//
fn create_discv_handshake(
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    port: String,
) -> Vec<u8> {
    let mut result = Vec::new();

    // First half is PUBLIC_KEY | PORT (in bytes)
    let first_half = public_key_and_port_to_vec(public_key, port);
    // Second half is H(PUBLIC_KEY | PORT)_C (in bytes)
    let second_half = hash_and_sign_message_digest(secret_key, result.clone());

    result.extend(first_half);
    result.extend(second_half);

    result
}

fn verify_discv_handshake(message: Vec<u8>) -> (bool, EcdsaPublicKey) {
    let (_, dummy_pk) = themis::keygen::gen_ec_key_pair().split();
    let full_length = message.len();
    if full_length > 243 || full_length < 241 {
        log::error!("message length not between 241 or 243");
        return (false, dummy_pk);
    }
    let public_key = match extract_pub_key_field(message.clone()) {
        Ok(k) => k,
        Err(e) => {
            log::error!("key extraction failed: {}", e);
            return (false, dummy_pk);
        }
    };
    let port = extract_port_addr_field(message.clone());
    let mut plain_message = Vec::new();
    plain_message.extend(public_key.clone());
    plain_message.extend(port);

    // a hack to make sure that the signed message does not include
    // zeros that the peer never intended to be part of the message
    let last_three_elements = message[full_length - 3..].to_vec();
    let trailing_zeros = check_zeros(last_three_elements);
    let signed_message = message[PUB_KEY_LEN + SRV_PORT_LEN..full_length - trailing_zeros].to_vec();

    let public_key = match EcdsaPublicKey::try_from_slice(public_key) {
        Ok(k) => k,
        Err(e) => {
            log::error!("could not restore public key from slice");
            return (false, dummy_pk);
        }
    };

    (
        cmp_message_with_signed_digest(public_key.clone(), plain_message, signed_message),
        public_key,
    )
}

const PUB_KEY_LEN: usize = 90;
const SRV_PORT_LEN: usize = 5;
fn extract_pub_key_field(v: Vec<u8>) -> Result<Vec<u8>, hex::FromHexError> {
    let v = v[..PUB_KEY_LEN].to_vec();
    Ok(hex::decode(v)?)
}

fn extract_port_addr_field(v: Vec<u8>) -> Vec<u8> {
    v[PUB_KEY_LEN..PUB_KEY_LEN + SRV_PORT_LEN].to_vec()
}

fn check_zeros(v: Vec<u8>) -> usize {
    let mut result = 0;
    for num in v.iter() {
        if *num == 0 {
            result += 1;
        }
    }
    result
}
