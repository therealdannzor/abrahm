use super::common::{extract_server_port_field, verify_p2p_message};
use super::udp_utils::{net_open, next_token};
use super::{FromServerEvent, InternalMessage, OrdPayload, PayloadEvent, PeerInfo};
use mio::{net::UdpSocket, Events, Interest, Token};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

pub async fn spawn_server_accept_loop(
    tx_out: Sender<InternalMessage>,
    tx_in: Sender<PayloadEvent>,
    validators: Vec<String>,
) {
    let join = tokio::spawn(async move {
        event_loop(tx_out, tx_in, validators).await;
    });

    let _ = join.await;
}

async fn event_loop(
    tx_out: Sender<InternalMessage>,
    tx_in: Sender<PayloadEvent>,
    validator_list: Vec<String>,
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

    let mut peers_with_token: Vec<String> = Vec::new();
    let mut token_to_socket: HashMap<Token, UdpSocket> = HashMap::new();
    tokio::spawn(async move {
        let tmp = socket.clone();
        let mut sok1 = tmp.lock().await;
        let tx2_out = tx_out.clone();

        loop {
            poller.poll(&mut events, /* no timeout */ None).unwrap();
            let mut nonce: u32 = 0;

            for event in events.iter() {
                match event.token() {
                    Token(1024) => loop {
                        let mut buf = [0; PEER_MESSAGE_MAX_LEN];
                        match sok1.recv_from(&mut buf) {
                            Ok((_, source_address)) => {
                                let (valid, peer_key) = verify_p2p_message(buf.to_vec());
                                if !valid {
                                    log::error!("server backend failed to verify message, discard");
                                    continue;
                                }
                                let peer_key = hex::encode(peer_key);
                                if !validator_list.contains(&peer_key) {
                                    log::warn!("peer not in whitelist");
                                    break;
                                } else if peers_with_token.contains(&peer_key) {
                                    log::warn!(
                                        "peer already given a new port to speak with, abort"
                                    );
                                }
                                if is_upgrade_syn_tag(buf.to_vec()) {
                                    let incoming_peer_server_port =
                                        extract_server_port_field(buf.to_vec());
                                    let addr = "127.0.0.1:0".parse().unwrap();
                                    // this is the upgraded socket which will from now on solely be used
                                    // for p2p messages between these two peers
                                    let mut ug_socket = UdpSocket::bind(addr).unwrap();
                                    let ug_token = next_token(&mut unique_token);
                                    let ug_port = ug_socket.local_addr().unwrap();
                                    let _ = poller.registry().register(
                                        &mut ug_socket,
                                        ug_token,
                                        INTERESTS,
                                    );
                                    let peer_dat = PeerInfo(peer_key.clone(), ug_token, ug_port);
                                    let new_client_message = InternalMessage::FromServerEvent(
                                        FromServerEvent::NewClient(peer_dat),
                                    );
                                    if let Err(e) = tx2_out.try_send(new_client_message) {
                                        log::error!(
                                            "server backend failed to send internal message: {}",
                                            e
                                        );
                                        break;
                                    }

                                    peers_with_token.push(peer_key);
                                    token_to_socket.insert(ug_token, ug_socket);
                                } else if is_upgrade_ack_tag(buf.to_vec()) {
                                    if !peers_with_token.contains(&peer_key) {
                                        log::warn!(
                                            "peer has not sent a upgrade syn message yet, abort"
                                        );
                                        break;
                                    }
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // this is normal, try again
                                break;
                            }
                            Err(e) => {
                                // something went really wrong
                                eprintln!("Server loop error occurred: {:?}", e);
                            }
                        };
                    },
                    Token(tok) => loop {
                        let socket = token_to_socket.get(&Token(tok)).unwrap();
                        let mut message_buf = [0; PEER_MESSAGE_MAX_LEN];
                        // message received from a known peer
                        match socket.recv_from(&mut message_buf) {
                            Ok((size, _)) => {
                                nonce += 1;
                                let message = message_buf[..size].to_vec();
                                log::info!("received message: {:?}, from: {}", message, tok);
                                let ord_pay = OrdPayload(message, nonce);
                                let new_message = PayloadEvent::StoreMessage(Token(tok), ord_pay);
                                let _ = tx_in.send(new_message);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => {
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

fn is_upgrade_ack_tag(v: Vec<u8>) -> bool {
    let expected = "UGACK".to_string().as_bytes().to_vec();
    v[90..95].to_vec() == expected
}
