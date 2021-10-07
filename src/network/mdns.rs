#![allow(unused)]

use super::common::cmp_message_with_signed_digest;
use crate::hashed;
use crate::swiss_knife::helper::{hash_from_vec_u8_input, sign_message_digest};
use futures::StreamExt;
use libp2p::{
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;

pub async fn peer_discovery_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    serv_port: String,
) -> Result<(), Box<dyn Error>> {
    let keys_id = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys_id.public());
    let transport = libp2p::development_transport(keys_id).await?;
    let behaviour = Mdns::new(MdnsConfig::default()).await?;

    let mut swarm = Swarm::new(transport, behaviour, peer_id);
    let assign_multi_addr = "/ip4/0.0.0.0/tcp/0".parse::<libp2p::Multiaddr>()?;
    swarm.listen_on(assign_multi_addr.clone());

    // create a counter to avoid spawning to servers
    let counter_1: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

    loop {
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
                            println!("Dispatched message to {}", recipient_addr);
                        }
                    });
                }
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                let mut counter = counter_1.lock().unwrap();
                // since we have two network interfaces we only want to spawn a listening server
                // for one of them (they have both the same port)
                if *counter == 1 {
                    let socket_addr = multi_to_socket_addr(address);
                    let socket = UdpSocket::bind(&socket_addr).await?;
                    let serv = Server {
                        socket,
                        buf: vec![0; 198],
                        to_send: None,
                    };
                    tokio::spawn(async move {
                        serv.run().await;
                    });
                } else {
                    *counter += 1;
                }
            }
            _ => {}
        }
    }
}

pub struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    to_send: Option<usize>,
}

impl Server {
    async fn run(self) -> Result<(), std::io::Error> {
        let Server {
            socket,
            mut buf,
            mut to_send,
        } = self;

        loop {
            let two_sec = std::time::Duration::from_secs(2);
            std::thread::sleep(two_sec);
            if let Some(size) = to_send {
                println!("Size of message: {}", buf.len());
                println!(
                    "Is valid handshake message: {}",
                    verify_discv_handshake(buf.clone())
                );
            }
            println!(
                "Nothing to send, receiving messages at {}",
                socket.local_addr().unwrap()
            );
            to_send = Some(socket.recv(&mut buf).await?);
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
    let mut first_half = public_key_and_port_to_vec(public_key, port);

    // Second half is H(PUBLIC_KEY | PORT)_C (in bytes)
    let second_half = hash_and_sign(first_half.clone(), secret_key);

    let mut result = Vec::new();
    result.extend(&first_half);
    result.extend(second_half);

    result
}

fn public_key_and_port_to_vec(key: EcdsaPublicKey, port: String) -> Vec<u8> {
    let mut res = key.as_ref().to_vec(); // this contains non ASCII characters
    res.extend(port.as_bytes().to_vec());
    res
}

fn hash_and_sign(input: Vec<u8>, secret_key: EcdsaPrivateKey) -> Vec<u8> {
    let hashed = hash_from_vec_u8_input(input.clone());
    let signed_hash = sign_message_digest(secret_key, hashed.as_ref());
    signed_hash
}

fn verify_discv_handshake(message: Vec<u8>) -> bool {
    // messages are between length 196 and 198
    if message.len() > 198 {
        panic!("incorrect size of handshake message: {}", message.len());
    }
    const PUB_KEY_LEN: usize = 45;
    const SRV_PORT_LEN: usize = 5;
    let public_key: &[u8] = &message[..PUB_KEY_LEN];
    let port: &[u8] = &message[PUB_KEY_LEN..PUB_KEY_LEN + SRV_PORT_LEN];
    let mut plain_message = Vec::new();
    plain_message.extend_from_slice(public_key);
    plain_message.extend_from_slice(port);
    let signed_message = message[PUB_KEY_LEN + SRV_PORT_LEN..].to_vec();

    let public_key = match EcdsaPublicKey::try_from_slice(public_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    cmp_message_with_signed_digest(public_key, plain_message, signed_message)
}
