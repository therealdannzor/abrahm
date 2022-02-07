#![allow(dead_code)]

use crate::common::{cmp_two_keys, cmp_two_keys_string};
use crate::message::{from_handshake, FixedHandshakes};
use std::io::{self, ErrorKind};
use std::sync::{Arc, Mutex};
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};

pub struct Pipes {
    rw: Option<Arc<Mutex<TcpStream>>>,

    // for mocks in test
    test_w: Option<TestPipeSend>,
    test_r: Option<TestPipeReceive>,
}

#[derive(Clone)]
pub struct TestPipeSend {
    w: broadcast::Sender<Vec<u8>>,
}
struct TestPipeReceive {
    r: broadcast::Receiver<Vec<u8>>,
}

impl Pipes {
    pub fn new(rw: Option<Arc<Mutex<TcpStream>>>, test_mode: bool) -> Self {
        let (mut test_w, mut test_r) = (None, None);
        if test_mode {
            let pipe_wr = setup_test_pipe();
            test_w = Some(pipe_wr.0);
            test_r = Some(pipe_wr.1);
        }
        Self { rw, test_w, test_r }
    }
}

pub async fn initiate_ping(
    rw: &Arc<Mutex<Option<TcpStream>>>,
    test_w: Option<TestPipeSend>,
    ping_msg: Vec<u8>,
    remote_id: EcdsaPublicKey,
    handshake_id: EcdsaPublicKey,
    three_way_handshake_counter: Arc<Mutex<usize>>,
) {
    let remote_id = remote_id.clone();

    let priority_id = cmp_two_keys(remote_id, handshake_id.clone());
    if priority_id == handshake_id {
        let tmp = rw.clone();
        match send(&tmp, test_w, ping_msg).await {
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

async fn send(
    rw: &Arc<Mutex<Option<TcpStream>>>,
    test_w: Option<TestPipeSend>,
    msg: Vec<u8>,
) -> Result<(), io::Error> {
    let l = msg.len();
    let tmp = rw.clone();
    let rw = tmp.lock().unwrap();
    if rw.is_some() {
        loop {
            let send = rw.as_ref().unwrap();
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
    } else if test_w.is_some() {
        let s = test_w.clone().unwrap().w;
        let _ = s.send(msg);
    } else {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "neither tcp stream nor test pipe exists",
        ));
    }

    Ok(())
}

pub async fn read_handshake_loop(
    rw: Arc<Mutex<Option<TcpStream>>>,
    test_w: Option<TestPipeSend>,
    handshakes: FixedHandshakes,
    mut updates: mpsc::Receiver<Vec<u8>>,
    remote_id: EcdsaPublicKey,
) {
    // True when attempted to send a ping
    let initiated_handshake: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // A peer P is considered _fully upgraded_ with the client C if and only if:
    // 1) C sent a ping to P, P responded with pong, and C sent an ack; or
    // 2) P sent a ping to C, C responded with pong, and P sent an ack
    // Values:
    // 0 = has neither sent a ping not received a ping
    // 1 = sent or received a ping
    // 2 = sent or received a pong
    // 3 = sent or received an ack
    let three_way_handshake_counter: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

    let local_id = hex::encode(handshakes.author_id());
    let priority_id = cmp_two_keys_string(hex::encode(remote_id.clone()), local_id.clone());
    let tmp = rw.clone();
    if priority_id == local_id {
        initiate_ping(
            &tmp,
            test_w.clone(),
            handshakes.ping(),
            remote_id.clone(),
            handshakes.author_id(),
            three_way_handshake_counter.clone(),
        )
        .await;
    }

    loop {
        while let Some(msg) = updates.recv().await {
            let mut hs_phase = three_way_handshake_counter.lock().unwrap();
            let has_init = initiated_handshake.lock().unwrap();

            // all messages sent on this channel has already been checked with `from_handshake` and
            // are error-free hence the unwrap
            let parsed_msg = from_handshake(msg, remote_id.clone()).unwrap();

            // this peer has neither received a ping nor sent one
            if *hs_phase == 0 && !*has_init {
                if parsed_msg.code() == "ping" {
                    *hs_phase = 1;
                    let pong_msg = handshakes.pong();
                    let tmp = rw.clone();
                    match send(&tmp, test_w.clone(), pong_msg).await {
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
                    match send(&tmp, test_w.clone(), ack_msg).await {
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

async fn message_listen_loop(
    stream: Option<Arc<Mutex<TcpStream>>>,
    stream_id: EcdsaPublicKey,
    test_rcv: Option<Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>,
    fetcher: mpsc::Sender<Vec<u8>>,
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
                    let message_vec = buf.to_vec();
                    let _ = match from_handshake(message_vec.clone(), stream_id.clone()) {
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
    } else if test_rcv.is_some() {
        loop {
            let arc = test_rcv.clone().unwrap();
            let mut read = arc.lock().unwrap();
            while let Some(rx_msg) = read.recv().await {
                let _ = match from_handshake(rx_msg.clone(), stream_id.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = err.send(e.to_string()).await;
                        continue;
                    }
                };
                let _ = fetcher.send(rx_msg).await;
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
    use crate::message::FixedHandshakes;
    use themis::keygen;

    #[tokio::test]
    async fn full_three_way_handshakes_between_two_peers() {
        let (a_sk, a_pk) = keygen::gen_ec_key_pair().split();
        let (b_sk, b_pk) = keygen::gen_ec_key_pair().split();
        let a_hs = FixedHandshakes::new(a_pk.clone(), "8080".to_string(), a_sk).unwrap();
        let b_hs = FixedHandshakes::new(b_pk.clone(), "8081".to_string(), b_sk).unwrap();
    }
}
