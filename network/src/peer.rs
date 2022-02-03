#![allow(dead_code)]

use crate::message::{from_handshake, new_handshake, FixedHandshakes, HandshakeCode};
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

    // Client handshakes
    handshakes: FixedHandshakes,

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
    w: broadcast::Sender<[u8; MAX_LENGTH]>,
}
pub struct TestPipeReceive {
    r: broadcast::Receiver<[u8; MAX_LENGTH]>,
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
            last_seen,
            three_way_handshake_counter,
            initiated,
            close_recv,
            close_send,
            test_send,
            test_recv,
        }
    }

    async fn read_handshake_loop(&mut self, err: broadcast::Sender<io::Error>) {
        loop {
            let msg = match self.recv().await {
                Ok(x) => x.to_vec(),
                Err(e) => {
                    let _ = err.send(e);
                    continue;
                }
            };
            match from_handshake(msg, self.id.clone()) {
                Ok(_msg) => {
                    self.last_seen = new_timestamp();

                    let hs_phase = *self.three_way_handshake_counter.lock().unwrap();
                    let mut has_init = self.initiated.lock().unwrap();
                    if hs_phase == 0 && !*has_init {
                        *has_init = true;
                        let _ping_msg = self.handshakes.ping();
                        unimplemented!();
                    }
                }
                Err(e) => {
                    let _ = err.send(io::Error::new(ErrorKind::Other, e.to_string()));
                }
            };
            continue;
        }
    }

    pub async fn send(&self, msg: [u8; MAX_LENGTH]) -> Result<(), io::Error> {
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

    async fn recv(&self) -> Result<[u8; MAX_LENGTH], io::Error> {
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
                        return Ok(buf);
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
