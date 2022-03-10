#![allow(dead_code)]

use crate::common::{cmp_two_keys, cmp_two_keys_string};
use crate::message::{from_handshake, FixedHandshakes};
use crate::utils::get_tcp_and_addr;
use crate::HandshakeAPI;
use std::io::{self, ErrorKind};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

/// Runs the p2p connection stream and returns two channels to interact with the multiple loops.
/// The first channel is the API handle, used to query the current handshake state (phase).
/// The second channel is the error channel. This should be error free, thus empty.
pub async fn peer_handshake_loop(
    other_stream: Option<Arc<TcpListener>>,
    other_stream_id: EcdsaPublicKey,
    mock_recv: Option<broadcast::Receiver<Vec<u8>>>,
    mock_send: Option<broadcast::Sender<Vec<u8>>>,
    handshakes: FixedHandshakes,
    mock_mode: bool,
) -> (mpsc::Sender<HandshakeAPI>, mpsc::Receiver<String>) {
    let (msg_send, msg_recv): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel(16);
    let (err_send, err_recv): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel(4);
    let (api_send, api_recv): (mpsc::Sender<HandshakeAPI>, mpsc::Receiver<HandshakeAPI>) =
        mpsc::channel(8);
    let rw = other_stream.clone();
    let api_handle = api_send.clone();

    // unit and e2e testing
    if mock_mode {
        message_listen_loop_mock(
            mock_recv.unwrap(),
            other_stream_id.clone(),
            msg_send.clone(),
            err_send.clone(),
        );
        read_handshake_loop(
            None,
            mock_send,
            handshakes,
            msg_recv,
            api_send.clone(),
            api_recv,
            other_stream_id,
        )
        .await;
    }
    // main operation
    else {
        tokio::spawn(async move {
            read_handshake_loop(
                rw,
                None,
                handshakes,
                msg_recv,
                api_send.clone(),
                api_recv,
                other_stream_id.clone(),
            )
            .await;
        });
    }

    (api_handle, err_recv)
}

// Sends a ping message if the peer is supposed to initiate a three-way handshake
// which is the one with the "highest value" key is the initiator.
async fn initiate_ping(
    rw: Arc<TcpListener>,
    ping_msg: Vec<u8>,
    remote_id: EcdsaPublicKey,
    handshake_id: EcdsaPublicKey,
    handshake_counter: Arc<AtomicUsize>,
    send_api: mpsc::Sender<HandshakeAPI>,
    initiated: Arc<AtomicBool>,
) -> io::Result<()> {
    let remote_id = remote_id.clone();

    let priority_id = cmp_two_keys(remote_id, handshake_id.clone());
    if priority_id == handshake_id {
        match send(rw, ping_msg).await {
            Ok(_) => {
                update_counters(handshake_counter.clone(), send_api.clone(), 1).await;
                let arc = initiated.clone();
                arc.store(true, Ordering::SeqCst);

                log::warn!("handshake value: {:?}", handshake_counter);
            }
            Err(e) => {
                log::error!("failed to send ping: {:?}", e);
            }
        };
    } else {
        // do nothing, we do not engage with the remote peer but wait for a ping instead
        log::warn!("skip send ping, wait for other peer to initiate");
    }
    return Ok(());
}

async fn initiate_ping_mock(
    test_w: broadcast::Sender<Vec<u8>>,
    ping_msg: Vec<u8>,
    remote_id: EcdsaPublicKey,
    handshake_id: EcdsaPublicKey,
    handshake_counter: Arc<AtomicUsize>,
    send_api: mpsc::Sender<HandshakeAPI>,
    initiated: Arc<AtomicBool>,
) {
    let priority_id = cmp_two_keys(remote_id.clone(), handshake_id.clone());
    if priority_id == handshake_id {
        match send_mock(test_w, ping_msg).await {
            Ok(_) => {
                update_counters(handshake_counter.clone(), send_api.clone(), 1).await;
                let arc = initiated.clone();
                arc.store(true, Ordering::SeqCst);

                log::warn!("handshake value: {:?}", handshake_counter);
            }
            Err(e) => {
                log::error!("failed to send ping: {:?}", e);
            }
        };
    } else {
        return;
    }
}

// Writes a message to a TCP connection
async fn send(listener: Arc<TcpListener>, msg: Vec<u8>) -> Result<(), io::Error> {
    let l = msg.len();
    loop {
        match listener.clone().accept().await {
            Ok((stream, _)) => {
                let _ = stream.writable().await;

                match stream.try_write(&msg) {
                    Ok(n) => {
                        if n != l {
                            return Err(io::Error::new(
                                ErrorKind::BrokenPipe,
                                "sent incomplete message",
                            ));
                        }
                        return Ok(());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
            Err(e) => {
                log::error!("p2p message tcp accept failed: {}", e);
            }
        }
    }
}

// Writes a message to the mock tokio channel
async fn send_mock(
    test_w: broadcast::Sender<Vec<u8>>,
    msg: Vec<u8>,
) -> Result<usize, tokio::sync::broadcast::error::SendError<Vec<u8>>> {
    let s = test_w.clone();
    s.send(msg)
}

// Keeps track of the handshake state between local and remote node
// which forms a p2p connection
fn handshake_status_api(mut recv: mpsc::Receiver<HandshakeAPI>) {
    let state = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            while let Some(msg) = recv.recv().await {
                match msg {
                    HandshakeAPI::NewState(s) => {
                        if s > 0 {
                            state.clone().fetch_add(s as usize, Ordering::SeqCst);
                        } else {
                            state.clone().fetch_sub(s as usize, Ordering::SeqCst);
                        }
                    }
                    HandshakeAPI::GetState(sender) => {
                        let res = state.clone().load(Ordering::SeqCst);
                        let _ = sender.send(res as i32).unwrap();
                    }
                    HandshakeAPI::IsAuth(s) => {
                        let phase = state.clone().load(Ordering::SeqCst);
                        if phase == 3 {
                            let _ = s.send(true).unwrap();
                        } else {
                            let _ = s.send(false).unwrap();
                        }
                    }
                }
            }
        }
    });
}

// Receives messages from the fetcher channel (connected to the message listener loop).
// This function is responsible for managing the full handshake logic: receive and send of
// handshake messages.
async fn read_handshake_loop(
    rw: Option<Arc<TcpListener>>,
    test_w: Option<broadcast::Sender<Vec<u8>>>,
    handshakes: FixedHandshakes,
    mut fetcher_recv: mpsc::Receiver<Vec<u8>>,
    api_send: mpsc::Sender<HandshakeAPI>,
    api_recv: mpsc::Receiver<HandshakeAPI>,
    remote_id: EcdsaPublicKey,
) {
    // True when attempted to send a ping
    let initiated_handshake: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    // A peer P is considered _fully upgraded_ with the client C if and only if:
    // 1) C sent a ping to P, P responded with pong, and C sent an ack; or
    // 2) P sent a ping to C, C responded with pong, and P sent an ack
    //
    // Values of the counter:
    // 0 = has neither sent a ping nor received a ping
    // 1 = sent or received a ping
    // 2 = sent or received a pong
    // 3 = sent or received an ack
    let handshake_counter: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    // Create a replica counter in its own process to make it accessible to the rest of the system.
    // This should be in sync with `handshake_counter`.
    tokio::spawn(async move {
        handshake_status_api(api_recv);
    });

    let local_id = hex::encode(handshakes.author_id());
    let priority_id = cmp_two_keys_string(hex::encode(remote_id.clone()), local_id.clone());
    let tmp = rw.clone();
    if priority_id == local_id {
        if test_w.is_some() {
            initiate_ping_mock(
                test_w.clone().unwrap(),
                handshakes.ping(),
                remote_id.clone(),
                handshakes.author_id(),
                handshake_counter.clone(),
                api_send.clone(),
                initiated_handshake.clone(),
            )
            .await;
        } else {
            initiate_ping(
                tmp.unwrap(),
                handshakes.ping(),
                remote_id.clone(),
                handshakes.author_id(),
                handshake_counter.clone(),
                api_send.clone(),
                initiated_handshake.clone(),
            )
            .await;
        }
    }

    tokio::spawn(async move {
        loop {
            while let Some(msg) = fetcher_recv.recv().await {
                let atomic_phase = handshake_counter.clone().load(Ordering::SeqCst);
                let has_init = initiated_handshake.clone();

                // all messages sent on this channel have already been checked with `from_handshake` once
                // before arriving here and are thus error-free, hence the immediate unwrap
                let parsed_msg = match test_w {
                    Some(_) => from_handshake(msg, remote_id.clone()).unwrap(),
                    None => from_handshake(msg, handshakes.author_id().clone()).unwrap(),
                };

                // this peer has neither received a ping nor sent one
                if atomic_phase == 0 && has_init.load(Ordering::SeqCst) == false {
                    if parsed_msg.code() == "ping" {
                        update_counters(handshake_counter.clone(), api_send.clone(), 1).await;
                        let pong_msg = handshakes.pong();
                        if test_w.is_some() {
                            let write = test_w.clone();
                            let _ = send_mock(write.unwrap().clone(), pong_msg).await;
                        } else {
                            loop {
                                let tmp = rw.clone().unwrap();
                                let msg = pong_msg.clone();
                                match send(tmp, msg).await {
                                    Ok(_) => {
                                        break;
                                    }
                                    Err(e) => {
                                        log::error!("handshake send pong error: {}", e);
                                    }
                                };
                            }
                        }
                        update_counters(handshake_counter.clone(), api_send.clone(), 1).await;
                    } else {
                        log::warn!(
                            "handshake proto error: out of order, got: {}, expected ping",
                            parsed_msg.code()
                        );
                    }
                }
                // this peer has sent a ping and awaits a pong
                else if atomic_phase == 1 && has_init.load(Ordering::SeqCst) == true {
                    if parsed_msg.code() == "pong" {
                        update_counters(handshake_counter.clone(), api_send.clone(), 1).await;
                        let ack_msg = handshakes.ack();
                        if test_w.is_some() {
                            let write = test_w.clone();
                            let _ = send_mock(write.unwrap(), ack_msg).await;
                        } else {
                            loop {
                                let tmp = rw.clone().unwrap();
                                let msg = ack_msg.clone();
                                match send(tmp, msg).await {
                                    Ok(_) => {
                                        break;
                                    }
                                    Err(e) => {
                                        log::error!("handshake send ack error: {}", e);
                                    }
                                };
                            }
                        }
                        // handshake complete
                        update_counters(handshake_counter.clone(), api_send.clone(), 1).await;
                    }
                }
                // this peer has sent a pong message and awaits an ack
                else if atomic_phase == 2 && has_init.load(Ordering::SeqCst) == false {
                    if parsed_msg.code() == "ack" {
                        // handshake complete
                        update_counters(handshake_counter.clone(), api_send.clone(), 1).await;
                        break;
                    }
                }
            }
        }
    });
}

// Increments or decrements the handshake counter and notifies the api
async fn update_counters(
    counter: Arc<AtomicUsize>,
    replica_api: mpsc::Sender<HandshakeAPI>,
    value: i32,
) {
    if value > 0 {
        counter.clone().fetch_add(1, Ordering::SeqCst);
        let _ = replica_api.send(HandshakeAPI::NewState(value)).await;
    } else {
        let v = (-1 * value) as usize;
        counter.clone().fetch_sub(v, Ordering::SeqCst);
        let _ = replica_api.send(HandshakeAPI::NewState(value)).await;
    }
}

// Listens for p2p messages from the TCP stream. It then relays these messages to the fetcher.
pub async fn message_listen_loop(
    other_stream_id: EcdsaPublicKey,
    msg_fetcher: mpsc::Sender<Vec<u8>>,
    err: mpsc::Sender<String>,
) -> (Arc<TcpListener>, String) {
    let (rw, handshake_port) = get_tcp_and_addr().await;
    let rw = Arc::new(rw);
    let rw1 = rw.clone();

    tokio::spawn(async move {
        relay_message(rw1, other_stream_id, err, msg_fetcher).await;
    });

    (rw, handshake_port)
}

// Listens for p2p messages from the tokio broadcast channel. It then relays these messages to the fetcher.
fn message_listen_loop_mock(
    mut test_rcv: broadcast::Receiver<Vec<u8>>,
    public_key: EcdsaPublicKey,
    fetcher: mpsc::Sender<Vec<u8>>,
    err: mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        loop {
            while let Ok(rx_msg) = test_rcv.recv().await {
                let _ = match from_handshake(rx_msg.clone(), public_key.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = err.send(e.to_string()).await;
                        continue;
                    }
                };
                let _ = fetcher.clone().send(rx_msg).await;
            }
        }
    });
}

// Accepts an incoming connection from a listener and sends the message to fetcher
async fn relay_message(
    listener: Arc<TcpListener>,
    other_id: EcdsaPublicKey,
    err: mpsc::Sender<String>,
    msg_fetcher: mpsc::Sender<Vec<u8>>,
) {
    const MAX_LENGTH: usize = 1200;

    loop {
        match listener.clone().accept().await {
            Ok((stream, _)) => {
                let _ = stream.readable().await;
                let mut buf = [0; MAX_LENGTH];

                match stream.try_read(&mut buf) {
                    Ok(0) => {
                        continue;
                    }
                    Ok(_) => {
                        let message_vec = buf.to_vec();
                        let _ = match from_handshake(message_vec.clone(), other_id.clone()) {
                            Ok(_) => {}
                            Err(e) => {
                                let _ = err.send(e.to_string()).await;
                                continue;
                            }
                        };
                        let _ = msg_fetcher.send(message_vec).await;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        let _ = err.send(e.to_string()).await;
                    }
                }
            }
            Err(e) => {
                log::error!("p2p message tcp accept failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::peer_handshake_loop;
    use crate::common::cmp_two_keys;
    use crate::handshake_get_state;
    use crate::message::FixedHandshakes;
    use crate::HandshakeAPI;
    use themis::keygen::gen_ec_key_pair;
    use themis::keys::EcdsaKeyPair;
    use tokio::sync::{broadcast, mpsc};

    async fn sleep_one_half_second() {
        use tokio::time::{sleep, Duration};
        sleep(Duration::from_millis(500)).await;
    }

    fn create_two_pairs_highest_first() -> (EcdsaKeyPair, EcdsaKeyPair) {
        let pair1 = gen_ec_key_pair();
        let pair2 = gen_ec_key_pair();
        let (_, pub1) = pair1.clone().split();
        let (_, pub2) = pair2.clone().split();
        let highest = cmp_two_keys(pub1.clone(), pub2.clone());
        if highest == pub1 {
            return (pair1, pair2);
        } else {
            return (pair2, pair1);
        }
    }

    fn create_handshake_set_highest_first(
        pair_hi: EcdsaKeyPair,
        pair_lo: EcdsaKeyPair,
    ) -> (FixedHandshakes, FixedHandshakes) {
        let (hi_sk, hi_pk) = pair_hi.clone().split();
        let (lo_sk, lo_pk) = pair_lo.clone().split();
        let hi_shake = FixedHandshakes::new(hi_pk, "8080".to_string(), hi_sk).unwrap();
        let lo_shake = FixedHandshakes::new(lo_pk, "8081".to_string(), lo_sk).unwrap();
        (hi_shake, lo_shake)
    }

    struct MockPairPeer {
        high_keypair: EcdsaKeyPair,
        high_handshake: FixedHandshakes,
        low_keypair: EcdsaKeyPair,
        low_handshake: FixedHandshakes,
    }

    fn peer_credentials() -> MockPairPeer {
        let (high_keypair, low_keypair) = create_two_pairs_highest_first();
        let (high_handshake, low_handshake) =
            create_handshake_set_highest_first(high_keypair.clone(), low_keypair.clone());
        assert_eq!(
            high_keypair.clone().split().1.clone(),
            high_handshake.author_id()
        );
        assert_eq!(
            low_keypair.clone().split().1.clone(),
            low_handshake.author_id()
        );
        MockPairPeer {
            high_keypair,
            high_handshake,
            low_keypair,
            low_handshake,
        }
    }

    struct MockPeerHandlers {
        high_peer_handle: mpsc::Sender<HandshakeAPI>,
        high_err_handle: mpsc::Receiver<String>,
        low_peer_handle: mpsc::Sender<HandshakeAPI>,
        low_err_handle: mpsc::Receiver<String>,
    }

    async fn create_two_peer_loops() -> MockPeerHandlers {
        let mock = peer_credentials();
        let low_public_key = mock.low_keypair.split().1.clone();
        let high_public_key = mock.high_keypair.split().1.clone();
        let low_handshake = mock.low_handshake.clone();
        let high_handshake = mock.high_handshake.clone();
        assert_eq!(mock.high_handshake.author_id(), high_public_key.clone());
        assert_eq!(mock.low_handshake.author_id(), low_public_key.clone());

        // Create two broadcast channels to simulate communication between two peers.
        // We pass the receiver half of one peer to the other one to simulate p2p communication.
        let (fir_send, fir_recv) = broadcast::channel(8);
        let (sec_send, sec_recv) = broadcast::channel(8);

        let (high_peer_handle, high_err_handle) = peer_handshake_loop(
            None,
            low_public_key,
            Some(sec_recv),
            Some(fir_send),
            high_handshake,
            true,
        )
        .await;
        let (low_peer_handle, low_err_handle) = peer_handshake_loop(
            None,
            high_public_key,
            Some(fir_recv),
            Some(sec_send),
            low_handshake,
            true,
        )
        .await;
        MockPeerHandlers {
            high_peer_handle,
            high_err_handle,
            low_peer_handle,
            low_err_handle,
        }
    }

    async fn api_request_get(handle: mpsc::Sender<HandshakeAPI>, expected: i32) {
        let (response, api_msg) = handshake_get_state();
        let _ = handle.send(api_msg).await;

        match response.await {
            Ok(v) => assert_eq!(v, expected),
            Err(e) => panic!("request failed: {:?}", e),
        }
    }

    async fn api_error_check(mut handle: mpsc::Receiver<String>, expecting_error: bool) {
        if expecting_error {
            match handle.recv().await {
                Some(_) => {}
                None => {
                    panic!("missing error");
                }
            }
        } else {
            match handle.try_recv() {
                Ok(x) => {
                    // the channel has a message, we do not expect one to come
                    panic!("{}", x);
                }
                // channel is empty and returns an empty error, this is expected
                Err(e) if e == mpsc::error::TryRecvError::Empty => {}
                Err(e) => {
                    // something else happened, this is not expected
                    panic!("{}", e);
                }
            }
        }
    }

    #[tokio::test]
    async fn full_handshake() {
        let peer_handlers = create_two_peer_loops().await;
        let high_msg_api = peer_handlers.high_peer_handle.clone();
        let high_err_api = peer_handlers.high_err_handle;
        let low_msg_api = peer_handlers.low_peer_handle.clone();
        let low_err_api = peer_handlers.low_err_handle;

        // some time has passed for the two peers to go through the full handshake
        sleep_one_half_second().await;
        api_request_get(high_msg_api.clone(), 3).await;
        api_request_get(low_msg_api.clone(), 3).await;
        let expect_error = false;
        api_error_check(high_err_api, expect_error).await;
        api_error_check(low_err_api, expect_error).await;
    }
}
