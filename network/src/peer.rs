#![allow(dead_code)]

use crate::common::cmp_two_keys_string;
use crate::message::{from_handshake, FixedHandshakes};
use std::io::{self, ErrorKind};
use std::sync::{Arc, Mutex};
use swiss_knife::helper::new_timestamp;
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot};

// Peer is connected with the client (another running software instance, also a peer).
// It is part of the validator set which means its ID is already white listed.
pub struct Peer {
    rw: Option<TcpStream>,

    // ID of this peer
    id: EcdsaPublicKey,

    // Port to communicate with this peer
    port: String,

    // Handshakes signed by the client.
    // These have a different ID than that `id` of this struct.
    handshakes: FixedHandshakes,
    // Done with handshakes
    fully_upgraded: bool,

    // Last time a message was received
    last_seen: i64,

    // A peer P is considered _fully upgraded_ with the client C if and only if:
    // 1) C sent a ping to P, P responded with pong, and C sent an ack; or
    // 2) P sent a ping to C, C responded with pong, and P sent an ack
    // Values:
    // 0 = has neither sent a ping not received a ping
    // 1 = sent or received a ping
    // 2 = sent or received a pong
    // 3 = sent or received an ack
    three_way_handshake_counter: Arc<Mutex<usize>>,
    // True when attempted to send a ping
    initiated: Arc<Mutex<bool>>,

    // Exit signals
    close_recv: oneshot::Receiver<u8>,
    close_send: oneshot::Sender<u8>,

    // To mock tests
    test_send: Option<TestPipeSend>,
    test_recv: Option<TestPipeReceive>,
}

const MAX_LENGTH: usize = 550;

#[derive(Clone)]
pub struct TestPipeSend {
    w: broadcast::Sender<Vec<u8>>,
}
pub struct TestPipeReceive {
    r: broadcast::Receiver<Vec<u8>>,
}

pub fn setup_test_pipe() -> (TestPipeSend, TestPipeReceive) {
    let (tx, rx): (broadcast::Sender<Vec<u8>>, broadcast::Receiver<Vec<u8>>) =
        broadcast::channel(32);
    let send = TestPipeSend { w: tx };
    let recv = TestPipeReceive { r: rx };
    (send, recv)
}

impl Peer {
    pub fn new(
        rw: Option<TcpStream>,
        id: EcdsaPublicKey,
        handshakes: FixedHandshakes,
        test_send: Option<TestPipeSend>,
        test_recv: Option<TestPipeReceive>,
    ) -> Self {
        let port: String;
        if rw.is_some() {
            port = rw
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
                .to_string();
        } else {
            port = "8080".to_string();
        }
        let last_seen = new_timestamp();
        let three_way_handshake_counter = Arc::new(Mutex::new(0));
        let initiated = Arc::new(Mutex::new(false));
        let (close_send, close_recv): (oneshot::Sender<u8>, oneshot::Receiver<u8>) =
            oneshot::channel();
        Self {
            rw,
            id,
            port,
            handshakes,
            fully_upgraded: false,
            last_seen,
            three_way_handshake_counter,
            initiated,
            close_recv,
            close_send,
            test_send,
            test_recv,
        }
    }

    pub async fn send_ping_loop(&mut self, err: broadcast::Sender<io::Error>) {
        let remote_id = hex::encode(self.id.clone());
        let local_id = self.handshakes.author_id().clone();

        let priority_id = cmp_two_keys_string(remote_id, local_id.clone());
        let mut has_init = self.initiated.lock().unwrap();
        while !*has_init {
            if priority_id == local_id {
                match self.send_ping().await {
                    Ok(_) => {
                        *has_init = true;
                        let mut hs_phase = self.three_way_handshake_counter.lock().unwrap();
                        *hs_phase = 1;
                    }
                    Err(e) => {
                        let _ = err.send(e);
                    }
                };
            } else {
                // do nothing, we do not engage with the remote peer but wait for a ping instead
                let ok = io::Error::new(io::ErrorKind::Other, "waiting for other peer to initiate");
                let _ = err.send(ok);
                return;
            }
        }
    }

    pub async fn read_handshake_loop(&mut self) {
        loop {
            if self.fully_upgraded {
                log::info!("already upgraded, skip handshake step");
                continue;
            }
            let msg = match self.recv().await {
                Ok(x) => x.to_vec(),
                Err(e) => {
                    log::error!("handshake receive error: {}", e);
                    continue;
                }
            };
            match from_handshake(msg, self.id.clone()) {
                Ok(msg) => {
                    self.last_seen = new_timestamp();
                    let mut hs_phase = self.three_way_handshake_counter.lock().unwrap();
                    let has_init = self.initiated.lock().unwrap();

                    // this peer has neither received a ping nor sent one
                    if *hs_phase == 0 && !*has_init {
                        if msg.code() == "ping" {
                            *hs_phase += 1;
                            match self.send_pong().await {
                                Ok(_) => {
                                    *hs_phase += 1;
                                }
                                Err(e) => {
                                    log::error!("handshake send pong error: {}", e);
                                }
                            };
                        } else {
                            log::warn!(
                                "handshake proto error: out of order, got: {}, expected ping",
                                msg.code()
                            );
                        }
                    }
                    // this peer has sent a ping and awaits a pong
                    else if *hs_phase == 1 && *has_init {
                        if msg.code() == "pong" {
                            *hs_phase += 1;
                            match self.send_ack().await {
                                Ok(_) => {
                                    *hs_phase += 1;
                                    if *hs_phase == 3 {
                                        self.fully_upgraded = true;
                                    } else {
                                        log::error!("handshake proto error: incorrect phase, should be 3 but is: {}", *hs_phase);
                                    }
                                }
                                Err(e) => {
                                    log::error!("handshake send ack error: {}", e);
                                }
                            };
                        }
                        // edge case where both of the peers have sent a ping to one another
                        // approximately at the same time so we need to decide who will respond
                        // with a pong
                        else if msg.code() == "ping" {
                            let remote_id = msg.id();
                            let local_id = self.handshakes.author_id().clone();
                            let priority_id = cmp_two_keys_string(remote_id, local_id.clone());
                            if priority_id == local_id {
                                match self.send_pong().await {
                                    Ok(_) => {
                                        *hs_phase += 1;
                                    }
                                    Err(e) => {
                                        log::error!("handshake send pong error: {}", e);
                                    }
                                };
                            } else {
                                // do nothing, we wait for the remote peer to send a pong because
                                // its public key 'wins' over our public key and thus has priority
                            }
                        } else {
                            log::warn!(
                                "handshake proto error: out of order, got: {}, expected pong",
                                msg.code()
                            );
                        }
                    }
                    // this peer has sent a pong message and awaits an ack
                    else if *hs_phase == 2 && !*has_init {
                        if msg.code() == "ack" {
                            *hs_phase += 1;
                            if *hs_phase == 3 {
                                self.fully_upgraded = true;
                            } else {
                                log::error!("handshake proto error: incorrect phase, should be 3 but is: {}", *hs_phase);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("handshake error: {}", e.to_string());
                }
            };
            continue;
        }
    }

    pub async fn send_ping(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.ping()).await?)
    }

    pub async fn send_pong(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.pong()).await?)
    }

    pub async fn send_ack(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.ack()).await?)
    }

    async fn send(&self, msg: Vec<u8>) -> Result<(), io::Error> {
        let l = msg.len();
        if self.rw.is_some() {
            loop {
                let send = self.rw.as_ref().unwrap();
                let _ = send.writable().await;

                match send.try_write(&msg) {
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
        } else if self.test_send.is_some() {
            let s = self.test_send.clone().unwrap().w;
            let _ = s.send(msg);
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "neither tcp stream nor test pipe exists",
            ));
        }

        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, io::Error> {
        if self.rw.is_some() {
            loop {
                let recv = self.rw.as_ref().unwrap();
                let _ = recv.readable().await;
                let mut buf = [0; MAX_LENGTH];

                match recv.try_read(&mut buf) {
                    Ok(0) => {
                        continue;
                    }
                    Ok(_n) => {
                        return Ok(buf.to_vec());
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        } else if self.test_recv.is_some() && self.test_send.is_some() {
            let mut read = self.test_send.as_ref().unwrap().w.subscribe();
            if let Ok(msg) = read.recv().await {
                return Ok(msg);
            } else {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "received empty message",
                ));
            }
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "neither tcp stream nor test pipe exists",
            ));
        }
    }

    pub fn update_last_seen(&mut self) -> i64 {
        let ts = new_timestamp();
        self.last_seen = ts;
        ts
    }
}

#[cfg(test)]
mod tests {
    use super::{setup_test_pipe, Peer};
    use crate::message::FixedHandshakes;
    use themis::keygen;

    #[tokio::test]
    async fn full_three_way_handshakes_between_two_peers() {
        let (a_sk, a_pk) = keygen::gen_ec_key_pair().split();
        let (b_sk, b_pk) = keygen::gen_ec_key_pair().split();
        let a_hs = FixedHandshakes::new(a_pk.clone(), "8080".to_string(), a_sk).unwrap();
        let b_hs = FixedHandshakes::new(b_pk.clone(), "8081".to_string(), b_sk).unwrap();
        let (a_send, a_recv) = setup_test_pipe();
        let (b_send, b_recv) = setup_test_pipe();

        // simulate p2p messaging by assigning send/recv halves to both peers
        let _p1 = Peer::new(None, a_pk, a_hs, Some(b_send), Some(a_recv));
        let _p2 = Peer::new(None, b_pk, b_hs, Some(a_send), Some(b_recv));
    }
}
