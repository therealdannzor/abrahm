use super::common::{extract_server_port_field, verify_p2p_message};
use super::udp_utils::get_udp_and_addr;
use super::{FromServerEvent, OrdPayload, PayloadEvent, PeerInfo, UpgradedPeerData};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;

pub async fn spawn_server_accept_loop(
    tx_out: Sender<FromServerEvent>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: Sender<UpgradedPeerData>,
    validators: Vec<String>,
    notify: Arc<Notify>,
) {
    let join = tokio::spawn(async move {
        event_loop(tx_out, tx_in, tx2_in, validators, notify).await;
    });

    let _ = join.await;
}

async fn event_loop(
    tx_out: Sender<FromServerEvent>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: Sender<UpgradedPeerData>,
    validator_list: Vec<String>,
    notify: Arc<Notify>,
) -> Result<(), std::io::Error> {
    const PEER_MESSAGE_MAX_LEN: usize = 248;
    let mut stream_size: Option<usize> = None;
    let mut from_addr: Option<SocketAddr> = None;
    let mut buf = [0; PEER_MESSAGE_MAX_LEN];
    let wait_time = std::time::Duration::from_secs(2);

    // create listening server and register it will poll to receive events
    let (socket, port) = get_udp_and_addr().await;
    let sender = tx_out.clone();
    // spawn thread to not make Arc become mad
    tokio::spawn(async move {
        let host_port_msg = FromServerEvent::HostSocket(port);
        // inform the peer loop about where the server backend listens to
        let _ = sender.send(host_port_msg).await;
    });

    // peers stored as String
    let mut registered_peers = Vec::new();

    notify.notify_one();

    let tx_ug = tx2_in.clone();
    let mut nonce: u32 = 0;
    loop {
        if let Some(_) = stream_size {
            let start = std::time::Instant::now();
            log::warn!("stream is Some...");
            notify.notified().await;

            let (valid, peer_key_type) = verify_p2p_message(buf.to_vec());
            if !valid {
                log::error!("server backend failed to verify message, discard");
                continue;
            }
            let peer_key = hex::encode(peer_key_type.clone());
            if !validator_list.contains(&peer_key) {
                log::warn!("peer not in whitelist");
                continue;
            }
            if is_upgrade_syn_tag(buf.to_vec()) {
                log::debug!(
                    "received valid upgrade SYN message from {}",
                    from_addr.unwrap().port().to_string()
                );
                if registered_peers.contains(&peer_key) {
                    log::warn!("already registered this peer with its own token, abort");
                    continue;
                }
                let inc_serv_port = extract_server_port_field(buf.to_vec());
                let inc_serv_port = match std::str::from_utf8(&inc_serv_port) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        log::error!("could not convert incoming peer port to str: {}", e);
                        continue;
                    }
                };
                nonce += 1;
                log::debug!("send peer with id {} to task", nonce);
                let pi = PeerInfo(peer_key.clone(), nonce, inc_serv_port);
                let sender = tx_out.clone();
                tokio::spawn(async move {
                    log::debug!("sent data to client handle");
                    let new_client_message = FromServerEvent::NewClient(pi);
                    if let Err(e) = sender.send(new_client_message).await {
                        log::error!("server backend failed to send internal message: {}", e);
                    }
                });

                registered_peers.push(peer_key.clone());
                log::debug!("register peer with id {} as seen", nonce);

                continue;
            }
            let (is_valid, peer_id) = is_upgrade_ack_tag(buf.to_vec());
            if is_valid {
                log::debug!(
                    "received valid upgrade ACK message from {}, id: {}",
                    from_addr.unwrap().port().to_string(),
                    peer_id,
                );
                let new_port = extract_server_port_field(buf.to_vec());
                let new_port = match std::str::from_utf8(&new_port) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        log::error!("could not convert new peer port to str: {}", e);
                        continue;
                    }
                };
                let ug_data = UpgradedPeerData(peer_key_type.clone(), new_port, peer_id.into());
                let sender = tx_ug.clone();
                tokio::spawn(async move {
                    // inform the API that whenever the host wants to speak with
                    // this peer, make sure to use the `token_id` as identifier and
                    // the new port
                    if let Err(e) = sender.send(ug_data).await {
                        log::error!("server backend failed to send upgrade message: {}", e);
                    }
                });
            } else {
                log::error!("upgrade ack message invalid, discard");
            }

            let elapsed_time = start.elapsed();
            if let Some(time) = wait_time.checked_sub(elapsed_time) {
                tokio::time::sleep(time).await;
            }
        }
        buf = [0; PEER_MESSAGE_MAX_LEN];
        let (ss, fa) = socket.recv_from(&mut buf).await?;
        stream_size = Some(ss);
        from_addr = Some(fa);
        log::debug!("fetch new message from stream");
        notify.notify_one();
    }

    panic!("server loop exited, this should not happen");

    Ok(())
}

fn is_upgrade_syn_tag(v: Vec<u8>) -> bool {
    let expected = "UPGRD".to_string().as_bytes().to_vec();
    v[90..95].to_vec() == expected
}

fn is_upgrade_ack_tag(v: Vec<u8>) -> (bool, u8) {
    let expected = "ACK=".to_string().as_bytes().to_vec();
    let is_correct_tag = v[90..94].to_vec() == expected;
    let dig = v[94]; // digit 48 is '0' and digit 57 is '9'
    let is_num = dig >= 48 && dig <= 57;
    if is_correct_tag && is_num {
        (true, dig - 48)
    } else {
        (false, 0)
    }
}
