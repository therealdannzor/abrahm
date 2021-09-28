#![allow(unused)]

use super::udp_utils::{next_token, open_socket};
use super::{FromServerEvent, InternalMessage, OrdPayload, PayloadEvent, PeerInfo};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::{
    collections::{HashMap, VecDeque},
    io,
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub async fn spawn_event_listener(
    validator_list: Vec<String>,
) -> (
    Receiver<InternalMessage>,
    Sender<InternalMessage>,
    Receiver<PayloadEvent>,
    JoinHandle<()>,
) {
    let (fs_tx, fs_rx): (Sender<InternalMessage>, Receiver<InternalMessage>) = channel(32);
    let fs_tx_2 = fs_tx.clone();
    let (mailbox_tx, mailbox_rx): (Sender<PayloadEvent>, Receiver<PayloadEvent>) = channel(32);

    // receives from the event loop, should be plugged into the `peer_loop`
    let join = tokio::spawn(async move {
        let res = match event_loop(fs_tx, mailbox_tx, validator_list).await {
            Ok(()) => {}
            Err(e) => {
                panic!("event loop failed: {:?}", e);
            }
        };
    });

    (fs_rx, fs_tx_2, mailbox_rx, join)
}

async fn event_loop(
    fs_tx: Sender<InternalMessage>,
    mailbox_tx: Sender<PayloadEvent>,
    validator_list: Vec<String>,
) -> Result<(), io::Error> {
    const PEER_TOK: Token = Token(0);
    const SOCKET_TOK: Token = Token(1024); // token which represents the server
    const INTERESTS: Interest = Interest::READABLE.add(Interest::WRITABLE);
    const ECDSA_PUB_KEY_SIZE_BITS: usize = 90; // amount of characters the public key has (hexadecimal)
    const PEER_MESSAGE_MAX_LEN: usize = 256;

    let mut unique_token = Token(PEER_TOK.0 + 1);
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(16); // events correspond to amount of validators (AFAIK)

    // create listening server and register it will poll to receive events
    let (mut socket, sock_addr) = open_socket();
    let whoami_socket_message =
        InternalMessage::FromServerEvent(FromServerEvent::HostSocket(sock_addr));
    fs_tx.send(whoami_socket_message);

    let _ = poller
        .registry()
        .register(&mut socket, SOCKET_TOK, INTERESTS);

    loop {
        poller.poll(&mut events, /* no timeout */ None)?;
        let mut nonce: u32 = 0;

        for event in events.iter() {
            match event.token() {
                SOCKET_TOK => loop {
                    let mut handshake_key_buf = [0; ECDSA_PUB_KEY_SIZE_BITS];
                    match socket.recv_from(&mut handshake_key_buf) {
                        Ok((packet_size, source_address)) => {
                            if packet_size != ECDSA_PUB_KEY_SIZE_BITS {
                                log::warn!("handshake failed, does not contain public key of correct length");
                                break;
                            } else if std::str::from_utf8(
                                &handshake_key_buf[..ECDSA_PUB_KEY_SIZE_BITS],
                            )
                            .is_err()
                            {
                                log::warn!("handshake received but incorrect key format");
                                break;
                            }
                            let peer_key =
                                std::str::from_utf8(&handshake_key_buf[..ECDSA_PUB_KEY_SIZE_BITS])
                                    .unwrap()
                                    .to_string();
                            if !validator_list.contains(&peer_key) {
                                log::warn!("peer not in whitelist");
                                break;
                            }
                            let new_tok = next_token(&mut unique_token);
                            let _ = poller.registry().register(&mut socket, new_tok, INTERESTS);
                            let peer_dat = PeerInfo(peer_key, new_tok, source_address);
                            let new_client_message = InternalMessage::FromServerEvent(
                                FromServerEvent::NewClient(peer_dat),
                            );
                            fs_tx.send(new_client_message);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // this is normal, try again
                            break;
                        }
                        Err(e) => {
                            // something went really wrong
                            return Err(e);
                        }
                    };
                },
                client_token => loop {
                    let mut message_buf = [0; PEER_MESSAGE_MAX_LEN];
                    // message received from a known peer
                    match socket.recv_from(&mut message_buf) {
                        Ok((size, src)) => {
                            nonce += 1;
                            let message = message_buf[..size].to_vec();
                            let ord_pay = OrdPayload(message, nonce);
                            let new_message = PayloadEvent::Message(client_token, ord_pay);
                            mailbox_tx.send(new_message);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    };
                },
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
