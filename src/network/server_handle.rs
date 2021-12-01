use super::common::{extract_server_port_field, verify_p2p_message};
use super::udp_utils::{net_open, next_token};
use super::{
    FromServerEvent, InternalMessage, OrdPayload, PayloadEvent, PeerInfo, UpgradedPeerData,
};
use mio::{net::UdpSocket, Events, Interest, Token};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;

pub async fn spawn_server_accept_loop(
    tx_out: Sender<InternalMessage>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: Sender<UpgradedPeerData>,
    validators: Vec<String>,
    notify: Arc<Notify>,
) {
    let join = tokio::spawn(async move {
        event_loop(tx_out, tx_in, tx2_in, validators, notify).await;
    });

    let _ = join.await;
}

async fn event_loop(
    tx_out: Sender<InternalMessage>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: Sender<UpgradedPeerData>,
    validator_list: Vec<String>,
    notify: Arc<Notify>,
) {
    const ECDSA_PUB_KEY_SIZE_BITS: usize = 90; // amount of characters the public key has (hexadecimal)
    const PEER_MESSAGE_MAX_LEN: usize = 248;
    const PEER_TOK: Token = Token(0);
    const INTERESTS: Interest = Interest::READABLE.add(Interest::WRITABLE);

    let mut unique_token = Token(PEER_TOK.0 + 1);
    let mut events = Events::with_capacity(16); // events correspond to amount of validators (AFAIK)

    // create listening server and register it will poll to receive events
    let (mut poller, socket, sock_addr) = net_open();
    let payload = socket.clone();
    let sender = tx_out.clone();
    // spawn thread to not make Arc become mad
    tokio::spawn(async move {
        let whoami_socket_message =
            InternalMessage::FromServerEvent(FromServerEvent::HostSocket(sock_addr, payload));
        // inform the peer loop about where the server backend listens to
        let _ = sender.send(whoami_socket_message).await;
    });

    // peers stored as String
    let registered_peers = Arc::new(Mutex::new(Vec::new()));
    // map of 'Token' -> 'EcdsaPublicKey'
    let token_to_public = Arc::new(Mutex::new(HashMap::new()));
    // map of 'Token' -> 'UdpSocket' (protected by arc mutex)
    let mut token_to_socket: HashMap<Token, Arc<Mutex<UdpSocket>>> = HashMap::new();

    let sock = socket.clone();
    notify.notify_one();

    tokio::spawn(async move {
        let mut sok1 = sock.lock().unwrap();
        let tx2_out = tx_out.clone();
        let tx_ug = tx2_in.clone();

        loop {
            poller.poll(&mut events, /* no timeout */ None).unwrap();
            let mut nonce: u32 = 0;

            for event in events.iter() {
                match event.token() {
                    Token(1024) => loop {
                        counter += 1;
                        let mut buf = [0; PEER_MESSAGE_MAX_LEN];
                        match sok1.recv_from(&mut buf) {
                            Ok((_, source_address)) => {
                                let (valid, peer_key_type) = verify_p2p_message(buf.to_vec());
                                if !valid {
                                    log::error!("server backend failed to verify message, discard");
                                    continue;
                                }
                                let peer_key = hex::encode(peer_key_type.clone());
                                if !validator_list.contains(&peer_key) {
                                    log::warn!("peer not in whitelist");
                                    buf = [0; PEER_MESSAGE_MAX_LEN];
                                    continue;
                                }
                                if is_upgrade_syn_tag(buf.to_vec()) {
                                    log::debug!(
                                        "received valid upgrade SYN message from {}",
                                        source_address.port()
                                    );
                                    let arc = registered_peers.clone();
                                    let mut inner = arc.lock().unwrap();
                                    if inner.contains(&peer_key) {
                                        log::warn!("already registered this peer with its own token, abort");
                                        buf = [0; PEER_MESSAGE_MAX_LEN];
                                        continue;
                                    }
                                    drop(inner);
                                    drop(arc);
                                    let inc_serv_port = extract_server_port_field(buf.to_vec());
                                    let incoming_peer_server_port =
                                        match std::str::from_utf8(&inc_serv_port) {
                                            Ok(s) => s.to_string(),
                                            Err(e) => {
                                                log::error!(
                                                "could not convert incoming peer port to str: {}",
                                                e
                                            );
                                                buf = [0; PEER_MESSAGE_MAX_LEN];
                                                continue;
                                            }
                                        };
                                    let addr = "127.0.0.1:0".parse().unwrap();
                                    // this is the upgraded socket which will from now on solely be used
                                    // for p2p messages between these two peers
                                    let mut ug_socket = UdpSocket::bind(addr).unwrap();
                                    let ug_token = next_token(&mut unique_token);
                                    log::warn!("new token generated: {}", ug_token.0);
                                    let ug_port = ug_socket.local_addr().unwrap();
                                    let _ = poller.registry().register(
                                        &mut ug_socket,
                                        ug_token,
                                        INTERESTS,
                                    );
                                    let peer_dat = PeerInfo(
                                        peer_key.clone(),
                                        ug_token,
                                        ug_port,
                                        incoming_peer_server_port,
                                    );
                                    let sender = tx2_out.clone();
                                    tokio::spawn(async move {
                                        log::debug!("send data to client handle");
                                        let new_client_message = InternalMessage::FromServerEvent(
                                            FromServerEvent::NewClient(peer_dat),
                                        );
                                        if let Err(e) = sender.send(new_client_message).await {
                                            log::error!(
                                            "server backend failed to send internal message: {}",
                                            e
                                        );
                                        }
                                    });

                                    let arc = registered_peers.clone();
                                    let mut inner = arc.lock().unwrap();
                                    inner.push(peer_key.clone());
                                    drop(inner);
                                    token_to_socket
                                        .insert(ug_token, Arc::new(Mutex::new(ug_socket)));
                                    log::debug!("updated tok-to-sok with token {}", ug_token.0,);

                                    buf = [0; PEER_MESSAGE_MAX_LEN];
                                    continue;
                                }
                                let (is_valid, token_id) = is_upgrade_ack_tag(buf.to_vec());
                                if is_valid {
                                    log::debug!(
                                        "received valid upgrade ACK message from {} (short id: {})",
                                        source_address.port(),
                                        token_id,
                                    );
                                    let arc = token_to_public.clone();
                                    let mut inner = arc.lock().unwrap();
                                    if inner.get(&Token(token_id.into())).is_some() {
                                        log::warn!(
                                            "connection upgrade of token {} already confirmed",
                                            token_id
                                        );
                                        buf = [0; PEER_MESSAGE_MAX_LEN];
                                        continue;
                                    }
                                    let new_port = extract_server_port_field(buf.to_vec());
                                    let new_port = match std::str::from_utf8(&new_port) {
                                        Ok(s) => s.to_string(),
                                        Err(e) => {
                                            log::error!(
                                                "could not convert new peer port to str: {}",
                                                e
                                            );
                                            buf = [0; PEER_MESSAGE_MAX_LEN];
                                            continue;
                                        }
                                    };
                                    let ug_data = UpgradedPeerData(
                                        peer_key_type.clone(),
                                        new_port,
                                        Token(token_id.into()),
                                    );
                                    let sender = tx_ug.clone();
                                    tokio::spawn(async move {
                                        // inform the API that whenever the host wants to speak with
                                        // this peer, make sure to use the `token_id` as identifier and
                                        // the new port
                                        if let Err(e) = sender.send(ug_data).await {
                                            log::error!(
                                                "server backend failed to send upgrade message: {}",
                                                e
                                            );
                                        }
                                    });

                                    let arc = token_to_public.clone();
                                    let mut inner = arc.lock().unwrap();
                                    inner.insert(Token(token_id.into()), peer_key_type.clone());
                                    log::info!("server backend updated register with new upgraded peer: {}", token_id);
                                    buf = [0; PEER_MESSAGE_MAX_LEN];
                                } else {
                                    log::error!("upgrade ack message invalid, discard");
                                    buf = [0; PEER_MESSAGE_MAX_LEN];
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                log::debug!("blocked, try again");
                                buf = [0; PEER_MESSAGE_MAX_LEN];
                                // this is normal, try again
                                break;
                            }
                            Err(e) => {
                                buf = [0; PEER_MESSAGE_MAX_LEN];
                                // something went really wrong
                                log::error!("server loop recv error: {:?}", e);
                            }
                        };
                    },
                    Token(tok) => loop {
                        log::info!("Token {} event", tok);
                        let arc = token_to_socket.get(&Token(tok)).unwrap().clone();
                        let socket = arc.lock().unwrap();
                        let mut buf = [0; PEER_MESSAGE_MAX_LEN];
                        // message received from a known peer
                        match socket.recv_from(&mut buf) {
                            Ok((size, _)) => {
                                nonce += 1;
                                let message = buf[..size].to_vec();
                                log::info!("received message: {:?}, from: {}", message, tok);
                                let ord_pay = OrdPayload(message, nonce);
                                let new_message = PayloadEvent::StoreMessage(Token(tok), ord_pay);
                                let _ = tx_in.send(new_message);
                                buf = [0; PEER_MESSAGE_MAX_LEN];
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                buf = [0; PEER_MESSAGE_MAX_LEN];
                                break;
                            }
                            Err(e) => {
                                buf = [0; PEER_MESSAGE_MAX_LEN];
                                log::error!("server loop error ocurred: {:?}", e);
                            }
                        };
                    },
                }
            }
        }
    });
}

fn is_upgrade_syn_tag(v: Vec<u8>) -> bool {
    let expected = "UPGRD".to_string().as_bytes().to_vec();
    v[90..95].to_vec() == expected
}

fn is_upgrade_ack_tag(v: Vec<u8>) -> (bool, u8) {
    let expected = "ACK=".to_string().as_bytes().to_vec();
    let is_correct_tag = v[90..94].to_vec() == expected;
    let dig = v[95]; // digit 48 is '0' and digit 57 is '9'
    let is_num = dig >= 48 && dig <= 57;
    if is_correct_tag && is_num {
        (true, dig - 48)
    } else {
        (false, 0)
    }
}
