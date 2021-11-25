use super::common::verify_p2p_message;
use super::udp_utils::{net_open, next_token};
use super::{FromServerEvent, InternalMessage, OrdPayload, PayloadEvent, PeerInfo};
use mio::{Events, Interest, Token};
use std::io;
use tokio::sync::mpsc::Sender;

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

    tokio::spawn(async move {
        let tmp = socket.clone();
        let mut sok1 = tmp.lock().await;

        loop {
            poller.poll(&mut events, /* no timeout */ None).unwrap();
            let mut nonce: u32 = 0;

            for event in events.iter() {
                match event.token() {
                    Token(1024) => loop {
                        let mut buf = [0; PEER_MESSAGE_MAX_LEN];
                        match sok1.recv_from(&mut buf) {
                            Ok((packet_size, source_address)) => {
                                let (valid, peer_key) = verify_p2p_message(buf.to_vec());
                                if !valid {
                                    log::error!("server backend failed to verify message, discard");
                                    continue;
                                }
                                let peer_key = hex::encode(peer_key);
                                if !validator_list.contains(&peer_key) {
                                    log::warn!("peer not in whitelist");
                                    break;
                                }
                                let new_tok = next_token(&mut unique_token);
                                let _ = poller.registry().register(&mut *sok1, new_tok, INTERESTS);
                                let peer_dat = PeerInfo(peer_key, new_tok, source_address);
                                let new_client_message = InternalMessage::FromServerEvent(
                                    FromServerEvent::NewClient(peer_dat),
                                );
                                let _ = tx_out.send(new_client_message);
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
                        log::debug!("new connection from token: {}", tok);
                        let mut message_buf = [0; PEER_MESSAGE_MAX_LEN];
                        // message received from a known peer
                        match sok1.recv_from(&mut message_buf) {
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
