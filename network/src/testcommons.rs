use super::peer_handshake_loop;
use crate::common::cmp_two_keys;
use crate::handshake_get_state;
use crate::message::FixedHandshakes;
use crate::HandshakeAPI;
use themis::keygen::gen_ec_key_pair;
use themis::keys::EcdsaKeyPair;
use tokio::sync::{broadcast, mpsc};

pub async fn sleep_one_half_second() {
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

pub struct MockPairPeer {
    high_keypair: EcdsaKeyPair,
    high_handshake: FixedHandshakes,
    low_keypair: EcdsaKeyPair,
    low_handshake: FixedHandshakes,
}

pub fn peer_credentials() -> MockPairPeer {
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

pub async fn create_two_peer_loops() -> MockPeerHandlers {
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
