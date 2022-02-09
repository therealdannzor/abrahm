#![allow(dead_code)]

use crate::common::{cmp_two_keys, cmp_two_keys_string};
use crate::message::{from_handshake, FixedHandshakes};
use std::io::{self, ErrorKind};
use std::sync::{Arc, Mutex};
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

pub async fn peer_handshake_loop(
    rw: Arc<TcpStream>,
    other_stream_id: EcdsaPublicKey,
    handshakes: FixedHandshakes,
    test_send: Option<broadcast::Sender<Vec<u8>>>,
    test_rcv: Option<broadcast::Receiver<Vec<u8>>>,
    err: mpsc::Sender<String>,
) {
    let (send, recv): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel(16);
    let other_copy = other_stream_id.clone();
    let rw_copy = rw.clone();
    if test_rcv.is_some() {
        tokio::task::spawn(async move {
            message_listen_loop_mock(test_rcv.unwrap(), other_copy, send.clone(), err.clone())
                .await;
        });
    } else {
        tokio::task::spawn(async move {
            message_listen_loop(rw_copy, other_copy, send.clone(), err).await;
        });
    }

    read_handshake_loop(rw, test_send, handshakes, recv, other_stream_id).await;
}

// Sends a ping message if the peer is supposed to initiate a three-way handshake
// which is the one with the "highest value" key is the initiator.
async fn initiate_ping(
    rw: Arc<TcpStream>,
    ping_msg: Vec<u8>,
    remote_id: EcdsaPublicKey,
    handshake_id: EcdsaPublicKey,
    three_way_handshake_counter: Arc<Mutex<usize>>,
) {
    let remote_id = remote_id.clone();

    let priority_id = cmp_two_keys(remote_id, handshake_id.clone());
    if priority_id == handshake_id {
        let tmp = rw.clone();
        match send(tmp, ping_msg).await {
            Ok(_) => {
                let mut hs_phase = three_way_handshake_counter.lock().unwrap();
                *hs_phase = 1;
            }
            Err(e) => {
                log::error!("failed to send ping: {:?}", e);
            }
        };
    } else {
        // do nothing, we do not engage with the remote peer but wait for a ping instead
        log::warn!("skip send ping, wait for other peer to initiate");
        return;
    }
}

async fn initiate_ping_mock(
    test_w: broadcast::Sender<Vec<u8>>,
    ping_msg: Vec<u8>,
    remote_id: EcdsaPublicKey,
    handshake_id: EcdsaPublicKey,
    three_way_handshake_counter: Arc<Mutex<usize>>,
) {
    let priority_id = cmp_two_keys(remote_id.clone(), handshake_id.clone());
    if priority_id == handshake_id {
        match send_mock(test_w, ping_msg).await {
            Ok(_) => {
                let mut hs_phase = three_way_handshake_counter.lock().unwrap();
                *hs_phase = 1;
            }
            Err(e) => {
                log::error!("failed to send ping: {:?}", e);
            }
        };
    } else {
        return;
    }
}

// Writes a message to either a TCP connection or the mock tokio channel
async fn send(rw: Arc<TcpStream>, msg: Vec<u8>) -> Result<(), io::Error> {
    let l = msg.len();
    let rw = rw.clone();
    loop {
        let _ = rw.writable().await;

        match rw.try_write(&msg) {
            Ok(n) => {
                if n != l {
                    return Err(io::Error::new(
                        ErrorKind::BrokenPipe,
                        "sent incomplete message",
                    ));
                }
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

async fn send_mock(
    test_w: broadcast::Sender<Vec<u8>>,
    ping_msg: Vec<u8>,
) -> Result<usize, tokio::sync::broadcast::error::SendError<Vec<u8>>> {
    let s = test_w.clone();
    s.send(ping_msg)
}

// Receives messages from the fetcher channel (connected to the message listener loop).
// This function is responsible for managing the full handshake logic: receive and send of
// handshake messages.
async fn read_handshake_loop(
    rw: Arc<TcpStream>,
    test_w: Option<broadcast::Sender<Vec<u8>>>,
    handshakes: FixedHandshakes,
    mut fetcher_recv: mpsc::Receiver<Vec<u8>>,
    remote_id: EcdsaPublicKey,
) {
    // True when attempted to send a ping
    let initiated_handshake: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // A peer P is considered _fully upgraded_ with the client C if and only if:
    // 1) C sent a ping to P, P responded with pong, and C sent an ack; or
    // 2) P sent a ping to C, C responded with pong, and P sent an ack
    //
    // Values of the counter:
    // 0 = has neither sent a ping nor received a ping
    // 1 = sent or received a ping
    // 2 = sent or received a pong
    // 3 = sent or received an ack
    let three_way_handshake_counter: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

    let local_id = hex::encode(handshakes.author_id());
    let priority_id = cmp_two_keys_string(hex::encode(remote_id.clone()), local_id.clone());
    let tmp = rw.clone();
    if priority_id == local_id {
        if test_w.is_some() {
            initiate_ping_mock(
                test_w.unwrap(),
                handshakes.ping(),
                remote_id.clone(),
                handshakes.author_id(),
                three_way_handshake_counter.clone(),
            )
            .await;
        } else {
            initiate_ping(
                tmp,
                handshakes.ping(),
                remote_id.clone(),
                handshakes.author_id(),
                three_way_handshake_counter.clone(),
            )
            .await;
        }
    }

    loop {
        while let Some(msg) = fetcher_recv.recv().await {
            let mut hs_phase = three_way_handshake_counter.lock().unwrap();
            let has_init = initiated_handshake.lock().unwrap();

            // all messages sent on this channel have already been checked with `from_handshake` once
            // before arriving here and are thus error-free, hence the immediate unwrap
            let parsed_msg = from_handshake(msg, remote_id.clone()).unwrap();

            // this peer has neither received a ping nor sent one
            if *hs_phase == 0 && !*has_init {
                if parsed_msg.code() == "ping" {
                    *hs_phase = 1;
                    let pong_msg = handshakes.pong();
                    let tmp = rw.clone();
                    match send(tmp, pong_msg).await {
                        Ok(_) => {
                            *hs_phase = 2;
                        }
                        Err(e) => {
                            log::error!("handshake send pong error: {}", e);
                        }
                    };
                } else {
                    log::warn!(
                        "handshake proto error: out of order, got: {}, expected ping",
                        parsed_msg.code()
                    );
                }
            }
            // this peer has sent a ping and awaits a pong
            else if *hs_phase == 1 && *has_init {
                if parsed_msg.code() == "pong" {
                    let ack_msg = handshakes.ack();
                    let tmp = rw.clone();
                    match send(tmp, ack_msg).await {
                        Ok(_) => {
                            *hs_phase = 3;
                        }
                        Err(e) => {
                            log::error!("handshake send ack error: {}", e);
                        }
                    };
                }
            }
            // this peer has sent a pong message and awaits an ack
            else if *hs_phase == 2 && !*has_init {
                if parsed_msg.code() == "ack" {
                    *hs_phase = 3;
                }
            }
        }
    }
}

// Listens for p2p messages from the TCP stream. It then relays these messages to the fetcher.
async fn message_listen_loop(
    rw: Arc<TcpStream>,
    other_stream_id: EcdsaPublicKey,
    fetcher: mpsc::Sender<Vec<u8>>,
    err: mpsc::Sender<String>,
) {
    const MAX_LENGTH: usize = 400;
    let arc = rw.clone();
    loop {
        let _ = arc.readable().await;
        let mut buf = [0; MAX_LENGTH];

        match arc.try_read(&mut buf) {
            Ok(0) => {
                continue;
            }
            Ok(_) => {
                let message_vec = buf.to_vec();
                let _ = match from_handshake(message_vec.clone(), other_stream_id.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = err.send(e.to_string()).await;
                        continue;
                    }
                };
                let _ = fetcher.send(message_vec).await;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                let _ = err.send(e.to_string()).await;
            }
        }
    }
}

// Listens for p2p messages from the tokio broadcast channel. It then relays these messages to the fetcher.
async fn message_listen_loop_mock(
    mut test_rcv: broadcast::Receiver<Vec<u8>>,
    other_stream_id: EcdsaPublicKey,
    fetcher: mpsc::Sender<Vec<u8>>,
    err: mpsc::Sender<String>,
) {
    loop {
        while let Ok(rx_msg) = test_rcv.recv().await {
            let _ = match from_handshake(rx_msg.clone(), other_stream_id.clone()) {
                Ok(_) => {}
                Err(e) => {
                    let _ = err.send(e.to_string()).await;
                    continue;
                }
            };
            let _ = fetcher.clone().send(rx_msg).await;
        }
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn full_three_way_handshakes_between_two_peers() {}
}
