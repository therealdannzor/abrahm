#![allow(dead_code)]

use crate::common::{cmp_two_keys, cmp_two_keys_string};
use crate::message::{from_handshake, FixedHandshakes, RawHandshake};
use std::io::{self, ErrorKind};
use std::sync::{Arc, Mutex};
use swiss_knife::helper::new_timestamp;
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};

pub struct Pipes {
    rw: Option<Arc<Mutex<TcpStream>>>,

    // for mocks in test
    test_w: Option<TestPipeSend>,
    test_r: Option<TestPipeReceive>,

    // Handshakes signed by the client.
    // These have a different ID than that `id` of this struct.
    handshakes: FixedHandshakes,

    // True when attempted to send a ping
    initiated_handshake: Arc<Mutex<bool>>,

    // Last time a stream was received
    last_received: i64,

    // A peer P is considered _fully upgraded_ with the client C if and only if:
    // 1) C sent a ping to P, P responded with pong, and C sent an ack; or
    // 2) P sent a ping to C, C responded with pong, and P sent an ack
    // Values:
    // 0 = has neither sent a ping not received a ping
    // 1 = sent or received a ping
    // 2 = sent or received a pong
    // 3 = sent or received an ack
    three_way_handshake_counter: Arc<Mutex<usize>>,
}

#[derive(Clone)]
struct TestPipeSend {
    w: broadcast::Sender<Vec<u8>>,
}
struct TestPipeReceive {
    r: broadcast::Receiver<Vec<u8>>,
}

impl Pipes {
    pub fn new(
        rw: Option<Arc<Mutex<TcpStream>>>,
        test_mode: bool,
        handshakes: FixedHandshakes,
    ) -> Self {
        let (mut test_w, mut test_r) = (None, None);
        if test_mode {
            let pipe_wr = setup_test_pipe();
            test_w = Some(pipe_wr.0);
            test_r = Some(pipe_wr.1);
        }
        Self {
            rw,
            test_w,
            test_r,
            handshakes,
            initiated_handshake: Arc::new(Mutex::new(false)),
            last_received: 0,
            three_way_handshake_counter: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn send_ping_loop(
        &self,
        remote_id: EcdsaPublicKey,
        three_way_handshake_counter: Arc<Mutex<usize>>,
    ) {
        let remote_id = remote_id.clone();
        let local_id = self.handshakes.author_id().clone();

        let priority_id = cmp_two_keys(remote_id, local_id.clone());
        let mut has_init = self.initiated_handshake.lock().unwrap();
        while !*has_init {
            if priority_id == local_id {
                match self.send_ping().await {
                    Ok(_) => {
                        *has_init = true;
                        let mut hs_phase = three_way_handshake_counter.lock().unwrap();
                        *hs_phase = 1;
                    }
                    Err(e) => {
                        log::error!("failed to send ping: {:?}", e);
                    }
                };
            } else {
                // do nothing, we do not engage with the remote peer but wait for a ping instead
                log::error!("skip send ping, wait for other peer to initiate");
                return;
            }
        }
    }

    async fn send_ping(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.ping()).await?)
    }

    async fn send_pong(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.pong()).await?)
    }

    async fn send_ack(&self) -> Result<(), io::Error> {
        Ok(self.send(self.handshakes.ack()).await?)
    }

    async fn send(&self, msg: Vec<u8>) -> Result<(), io::Error> {
        let l = msg.len();
        if self.rw.is_some() {
            loop {
                let send = self.rw.as_ref().unwrap().lock().unwrap();
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
        } else if self.test_w.is_some() {
            let s = self.test_w.clone().unwrap().w;
            let _ = s.send(msg);
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "neither tcp stream nor test pipe exists",
            ));
        }

        Ok(())
    }

    pub async fn read_handshake_loop(&mut self, mut updates: mpsc::Receiver<RawHandshake>) {
        loop {
            while let Some(msg) = updates.recv().await {
                self.last_received = new_timestamp();
                let mut hs_phase = self.three_way_handshake_counter.lock().unwrap();
                let has_init = self.initiated_handshake.lock().unwrap();

                // this peer has neither received a ping nor sent one
                if *hs_phase == 0 && !*has_init {
                    if msg.code() == "ping" {
                        *hs_phase = 1;
                        match self.send_pong().await {
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
                            msg.code()
                        );
                    }
                }
                // this peer has sent a ping and awaits a pong
                else if *hs_phase == 1 && *has_init {
                    if msg.code() == "pong" {
                        match self.send_ack().await {
                            Ok(_) => {
                                *hs_phase = 3;
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
                        let local_id = hex::encode(self.handshakes.author_id().clone());
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
                        *hs_phase = 3;
                    }
                }
            }
            continue;
        }
    }

    async fn recv(&self) {
        if self.rw.is_some() {}
    }

    fn update_last_received(&mut self) {
        let ts = new_timestamp();
        self.last_received = ts;
    }
}

async fn message_box(
    returner: mpsc::Sender<RawHandshake>,
    mut fetcher: mpsc::Receiver<RawHandshake>,
) {
    loop {
        while let Some(msg) = fetcher.recv().await {
            let _ = returner.send(msg).await;
        }
    }
}

async fn message_listen_loop(
    stream: Option<Arc<Mutex<TcpStream>>>,
    stream_id: EcdsaPublicKey,
    test_rcv: Option<Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>,
    fetcher: mpsc::Sender<RawHandshake>,
    err: mpsc::Sender<String>,
) {
    const MAX_LENGTH: usize = 400;
    if stream.is_some() {
        loop {
            let s = stream.as_ref().unwrap().lock().unwrap();
            let _ = s.readable().await;
            let mut buf = [0; MAX_LENGTH];

            match s.try_read(&mut buf) {
                Ok(0) => {
                    continue;
                }
                Ok(_) => {
                    let h = match from_handshake(buf.to_vec(), stream_id.clone()) {
                        Ok(x) => x,
                        Err(e) => {
                            let _ = err.send(e.to_string()).await;
                            continue;
                        }
                    };
                    let _ = fetcher.send(h).await;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    let _ = err.send(e.to_string()).await;
                }
            }
        }
    } else if test_rcv.is_some() {
        loop {
            let arc = test_rcv.clone().unwrap();
            let mut read = arc.lock().unwrap();
            while let Some(rx_msg) = read.recv().await {
                let h = match from_handshake(rx_msg, stream_id.clone()) {
                    Ok(x) => x,
                    Err(e) => {
                        let _ = err.send(e.to_string()).await;
                        continue;
                    }
                };
                let _ = fetcher.send(h).await;
            }
        }
    } else {
        let _ = err.send("missing pipe(s), exit".to_string()).await;
    }
}

fn setup_test_pipe() -> (TestPipeSend, TestPipeReceive) {
    let (tx, rx): (broadcast::Sender<Vec<u8>>, broadcast::Receiver<Vec<u8>>) =
        broadcast::channel(32);
    let send = TestPipeSend { w: tx };
    let recv = TestPipeReceive { r: rx };
    (send, recv)
}

// Peer is connected with the client (another running software instance, also a peer).
// It is part of the validator set which means its ID is already white listed.
pub struct Peer {
    // TCP stream and mock channels
    pipes: Pipes,

    // ID of this peer
    id: EcdsaPublicKey,

    // Port to communicate with this peer
    port: String,

    // Done with handshakes
    fully_upgraded: bool,

    // Exit signals
    close_recv: oneshot::Receiver<u8>,
    close_send: oneshot::Sender<u8>,
}

impl Peer {
    pub fn new(pipes: Pipes, id: EcdsaPublicKey) -> Self {
        let port: String;
        if pipes.rw.is_some() {
            port = pipes
                .rw
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
                .to_string();
        } else {
            port = "8080".to_string();
        }
        let (close_send, close_recv): (oneshot::Sender<u8>, oneshot::Receiver<u8>) =
            oneshot::channel();
        Self {
            pipes,
            id,
            port,
            fully_upgraded: false,
            close_recv,
            close_send,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{setup_test_pipe, Peer, Pipes};
    use crate::message::FixedHandshakes;
    use themis::keygen;

    #[tokio::test]
    async fn full_three_way_handshakes_between_two_peers() {
        let (a_sk, a_pk) = keygen::gen_ec_key_pair().split();
        let (b_sk, b_pk) = keygen::gen_ec_key_pair().split();
        let a_hs = FixedHandshakes::new(a_pk.clone(), "8080".to_string(), a_sk).unwrap();
        let b_hs = FixedHandshakes::new(b_pk.clone(), "8081".to_string(), b_sk).unwrap();
        let a_pipe = Pipes::new(None, true, a_hs);
        let b_pipe = Pipes::new(None, true, b_hs);

        // simulate p2p messaging by assigning send/recv halves to both peers
        //let _p1 = Peer::new(None, a_pk, a_hs, Some(b_send), Some(a_recv));
        //let _p2 = Peer::new(None, b_pk, b_hs, Some(a_send), Some(b_recv));
    }
}
