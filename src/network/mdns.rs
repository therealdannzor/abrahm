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
) -> JoinHandle<()> {
    let join = tokio::spawn(async move {
        match peer_discovery_loop(pk, sk, serv_port, tx).await {
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
                        loop {
                            let three_sec = std::time::Duration::from_secs(3);
                            std::thread::sleep(three_sec);
                            let _ = socket
                                .send_to(&broadcast_disc_msg, recipient_addr.clone())
                                .await;
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
                        buf: vec![0; 198],
                        stream_size: None,
                    };
                    tokio::spawn(async move {
                        let _ = serv.run(tx).await;
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
    async fn run(self, tx: Sender<ValidatedPeer>) -> Result<(), std::io::Error> {
        let Server {
            socket,
            mut buf,
            mut stream_size,
        } = self;

        loop {
            let two_sec = std::time::Duration::from_secs(2);
            std::thread::sleep(two_sec);
            if let Some(_) = stream_size {
                if verify_discv_handshake(buf.clone()) {
                    log::info!("handshake verified!");
                    let port = extract_port_addr_field(buf.clone());
                    let public_key = extract_pub_key_field(buf.clone());
                    let validated = ValidatedPeer { port, public_key };
                    let _ = tx.send(validated).await;
                    buf = vec![0; 198];
                }
            }
            stream_size = Some(socket.recv(&mut buf).await?);
        }
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
    // First half is PUBLIC_KEY | PORT (in bytes)
    let mut result = public_key_and_port_to_vec(public_key, port);

    // Second half is H(PUBLIC_KEY | PORT)_C (in bytes)
    let second_half = hash_and_sign_message_digest(secret_key, result.clone());

    result.extend(second_half);
    result
}

fn verify_discv_handshake(message: Vec<u8>) -> bool {
    let full_length = message.len();
    // messages are between length 196 and 198
    if full_length > 198 || full_length < 196 {
        log::error!("message length not between 196 and 198");
        return false;
    }
    let public_key = extract_pub_key_field(message.clone());
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
        Err(_) => {
            log::error!("could not restore public key from slice");
            return false;
        }
    };

    cmp_message_with_signed_digest(public_key, plain_message, signed_message)
}

const PUB_KEY_LEN: usize = 45;
const SRV_PORT_LEN: usize = 5;
fn extract_pub_key_field(v: Vec<u8>) -> Vec<u8> {
    v[..PUB_KEY_LEN].to_vec()
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
