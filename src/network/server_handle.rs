use super::common::{extract_server_port_field, verify_p2p_message};
use super::udp_utils::get_udp_and_addr;
use super::{FromServerEvent, OrdPayload, PayloadEvent, PeerInfo, PeerShortId, UpgradedPeerData};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{Mutex, Notify};

pub async fn spawn_server_accept_loop(
    tx_out: Sender<FromServerEvent>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: UnboundedSender<UpgradedPeerData>,
    validators: Vec<String>,
    notify: Arc<Notify>,
    root_hash: String,
) {
    let join = tokio::spawn(async move {
        event_loop(tx_out, tx_in, tx2_in, validators, notify).await;
    });

    let _ = join.await;
}

async fn event_loop(
    tx_out: Sender<FromServerEvent>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: UnboundedSender<UpgradedPeerData>,
    validator_list: Vec<String>,
    notify: Arc<Notify>,
    root_hash: String,
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
    let mut registered_peers: Vec<String> = Vec::new();
    let mut upgraded_peers: Vec<String> = Vec::new();
    let mut registry_done = false;
    let mut upgrade_done = false;
    let mut root_hash_confirmed = false;
    let mut root_hash_peers: Vec<String> = Vec::new();

    // Public key mapped to short ID: String -> 'usize'
    let hex_key_to_id = Arc::new(Mutex::new(HashMap::<String, usize>::new()));

    notify.notify_one();

    let tx_ug = tx2_in.clone();
    let mut nonce: usize = 0;
    loop {
        buf = [0; PEER_MESSAGE_MAX_LEN];
        let stream_size = Some(socket.recv(&mut buf).await?);

        if let Some(_) = stream_size {
            if !upgrade_done {
                let (valid, peer_key_type) = verify_p2p_message(buf.to_vec());
                if !valid {
                    log::error!("server backend failed to verify message, discard");
                    continue;
                }
                let peer_key = hex::encode(peer_key_type.clone());
                let in_registered_list = registered_peers.contains(&peer_key);
                let in_upgraded_list = upgraded_peers.contains(&peer_key);
                let in_root_list = root_hash_peers.contains(&peers_key);
                if !validator_list.contains(&peer_key) {
                    log::warn!("peer not in whitelist");
                    continue;
                }
                if is_upgrade_syn_tag(buf.to_vec()) && !registry_done && !in_registered_list {
                    log::debug!("received valid upgrade SYN message",);
                    let inc_serv_port = extract_server_port_field(buf.to_vec());
                    let inc_serv_port = match std::str::from_utf8(&inc_serv_port) {
                        Ok(s) => s.to_string(),
                        Err(e) => {
                            log::error!("could not convert incoming peer port to str: {}", e);
                            continue;
                        }
                    };
                    nonce += 1;
                    let pi = PeerInfo(peer_key.clone(), nonce, inc_serv_port);
                    let sender = tx_out.clone();
                    let new_client_message = FromServerEvent::NewClient(pi);
                    if let Err(e) = sender.send(new_client_message).await {
                        log::error!("server backend failed to send internal message: {}", e);
                        continue;
                    }

                    registered_peers.push(peer_key.clone());
                    let arc = hex_key_to_id.clone();
                    let mut inner = arc.lock().await;
                    inner.insert(peer_key.clone(), nonce);
                    log::debug!("register peer with id {} as seen", nonce);
                    registry_done = registered_peers.len() == validator_list.len();
                    continue;
                }
                let (is_valid, peer_id) = is_upgrade_ack_tag(buf.to_vec());
                if is_valid && !upgrade_done && !in_upgraded_list {
                    log::debug!("received valid upgrade ACK message from id: {}", peer_id,);
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
                    // inform the API that whenever the host wants to speak with
                    // this peer, make sure to use the `token_id` as identifier and
                    // the new port
                    let _ = sender.send(ug_data);
                    upgraded_peers.push(peer_key.clone());
                    upgrade_done = upgraded_peers.len() == validator_list.len() - 1;
                    log::debug!(
                        "upgrades done: {}/{}",
                        upgraded_peers.len(),
                        validator_list.len() - 1
                    );
                } else {
                    log::error!("upgrade ACK message rejected, discard");
                }
                continue;
            }
            let (is_valid, peer_id) = is_root_hash_tag(buf.to_vec());
            if is_valid && !root_hash_confirmed && !in_root_list {
                let hash = extract_root_hash(buf.to_vec());
                if hash.is_none() {
                    log::error!("incorrect root hash, discard message");
                    continue;
                }
                let hash = hash.unwrap();
                if hash == root_hash {
                    root_hash_peers.push(peer_key);
                    log::info!(
                        "peer {} synced with local root hash, {} left",
                        peer_id,
                        validator_list.len() - 1 - root_hash_peers.len(),
                    )
                }
            } else {
                log::debug!("waiting for consensus message..");
            }
        }
    }

    Ok(())
}

fn is_upgrade_syn_tag(v: Vec<u8>) -> bool {
    let expected = "UPGRD".to_string().as_bytes().to_vec();
    v[90..95].to_vec() == expected
}

fn is_upgrade_ack_tag(v: Vec<u8>) -> (bool, u8) {
    let expected = "ACK=".to_string().as_bytes().to_vec();
    let is_correct_tag = v[90..90 + expected.len()].to_vec() == expected;
    let dig = v[94]; // digit 48 is '0' and digit 57 is '9'
    let is_num = dig >= 48 && dig <= 57;
    if is_correct_tag && is_num {
        (true, dig - 48)
    } else {
        (false, 0)
    }
}

fn is_root_hash_tag(v: Vec<u8>) -> (bool, u8) {
    let expected = "RTHASH".to_string().as_bytes().to_vec();
    let is_correct_tag = v[1..1 + expected.len()].to_vec() == expected;
    let dig = v[0];
    let is_num = dig >= 48 && dig <= 57;
    if is_correct_tag && is_num {
        (true, dig - 48)
    } else {
        (false, 0)
    }
}

fn extract_root_hash(v: Vec<u8>) -> Option<String> {
    let rh_len = 64;
    let root_hash = &v[7..7 + rh_len];
    match std::str::from_utf8(root_hash) {
        Ok(s) => {
            return Some(s.to_string());
        }
        Err(_) => return None,
    };
}
