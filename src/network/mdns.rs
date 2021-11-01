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
use rand::{
    distributions::{Distribution, Uniform},
    thread_rng,
};
use std::convert::TryInto;
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
                    log::debug!("broadcast discv message");
                    tokio::spawn(async move {
                        for _ in 0..9 {
                            let to_address = recipient_addr.clone();
                            let payload = broadcast_disc_msg.clone();
                            // let us pick a number [1, 5] to mitigate congestion
                            let one_to_five = create_rnd_number().try_into().unwrap();
                            let duration = tokio::time::Duration::from_secs(one_to_five);
                            tokio::time::sleep(duration);
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
                    log::debug!("start server buffer to receive other discv messages");
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

        let mut peers_confirmed = Vec::new();
        let wait_time = std::time::Duration::from_secs(2);
        let notif = tokio::sync::Notify::new();

        loop {
            if let Some(_) = stream_size {
                let start = std::time::Instant::now();

                notif.notified().await;
                let (is_verified, public_key) = verify_discv_handshake(buf.clone());
                if is_verified {
                    log::debug!("successful authentication of discv message read from buffer");
                    let public_hex = hex::encode(public_key.clone()).to_string();
                    // to make sure we don't count the same peer more than once
                    if peers_confirmed.contains(&public_hex) {
                        log::debug!("peer already confirmed, skip it");
                    } else {
                        let public_key_vec = public_key.as_ref().to_vec();
                        let port = extract_port_addr_field(buf.clone());
                        if to_find.clone().contains(&public_hex) {
                            // remove the peer already found in vector
                            if let Some(pos) = to_find.clone().iter().position(|x| *x == public_hex)
                            {
                                peers_confirmed.push(public_hex);
                                // if we have found all peers we are looking for, bail out
                                if peers_confirmed.len() == to_find.len() {
                                    log::info!("found and verified all peers, discovery done");
                                    return Ok(());
                                }
                            }
                            let validated = ValidatedPeer {
                                port,
                                public_key: public_key_vec,
                            };
                            let _ = tx.send(validated).await;
                        } else {
                            log::debug!("public hex not found in validator list");
                        }
                    }
                } else {
                    log::debug!("could not authenticate buffered message, discarding");
                }
                let elapsed_time = start.elapsed();
                if let Some(time) = wait_time.checked_sub(elapsed_time) {
                    tokio::time::sleep(time).await;
                }
            }
            buf.clear();
            buf = vec![0; 243];
            log::debug!("fetch new discovery messages");
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
    let second_half = hash_and_sign_message_digest(secret_key, first_half.clone());

    result.extend(first_half);
    result.extend(second_half);

    result
}

fn verify_discv_handshake(message: Vec<u8>) -> (bool, EcdsaPublicKey) {
    log::debug!("begin verification process of discv message");
    let (_, dummy_pk) = themis::keygen::gen_ec_key_pair().split();
    let full_length = message.len();
    if full_length > 243 || full_length < 241 {
        log::error!("message length not between 241 and 243");
        return (false, dummy_pk);
    }
    let public_key = match extract_pub_key_field(message.clone()) {
        Ok(k) => k,
        Err(e) => {
            log::error!("key extraction failed: {}", e);
            return (false, dummy_pk);
        }
    };

    let public_key = match EcdsaPublicKey::try_from_slice(public_key) {
        Ok(k) => k,
        Err(e) => {
            log::error!("could not restore public key from slice");
            return (false, dummy_pk);
        }
    };

    let port = extract_port_addr_field(message.clone());
    let port_str = match std::str::from_utf8(&port.clone()) {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("failure to convert port from utf-8 to string: {}", e);
            return (false, dummy_pk);
        }
    };
    //  Important to encode to hex again to mimic the process of how the sender
    //  created this message. If not, the public key will only be 45 character as
    //  opposed to the 90 characters it is in hex form.
    let pk_and_port_vec = public_key_and_port_to_vec(public_key.clone(), port_str);
    let mut plain_message = Vec::new();
    plain_message.extend(pk_and_port_vec);

    let signed_message = extract_signed_message(message);

    let auth_ok = cmp_message_with_signed_digest(public_key.clone(), plain_message, signed_message);
    log::debug!("message is signed by presumed peer: {}", auth_ok);
    (auth_ok, public_key)
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

fn extract_signed_message(v: Vec<u8>) -> Vec<u8> {
    let size = v.len();
    // a hack to make sure that the signed message does not include
    // zeros that the peer never intended to be part of the message
    let last_three_elements = v[size - 3..].to_vec();
    let trailing_zeros = check_zeros(last_three_elements);
    v[PUB_KEY_LEN + SRV_PORT_LEN..size - trailing_zeros].to_vec()
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

fn create_rnd_number() -> usize {
    let mut rng = thread_rng();
    let one_to_five = Uniform::new_inclusive(1, 5);
    one_to_five.sample(&mut rng)
}
