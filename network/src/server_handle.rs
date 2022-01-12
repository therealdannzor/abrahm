use super::common::{extract_server_port_field, verify_p2p_message, verify_root_hash_sync_message};
use super::message::MessageWorker;
use super::udp_utils::get_udp_and_addr;
use super::{FromServerEvent, PayloadEvent, PeerInfo, UpgradedPeerData};
use std::collections::HashMap;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, Notify};

pub async fn spawn_server_accept_loop(
    tx_out: Sender<FromServerEvent>,
    tx_in: Sender<PayloadEvent>,
    tx2_in: UnboundedSender<UpgradedPeerData>,
    validators: Vec<String>,
    notify: Arc<Notify>,
    root_hash: String,
    public: EcdsaPublicKey,
    secret: EcdsaPrivateKey,
) {
    let join = tokio::spawn(async move {
        let _ = event_loop(
            tx_out, tx_in, tx2_in, validators, notify, root_hash, public, secret,
        )
        .await;
    });

    let _ = join.await;
}

async fn event_loop(
    tx_out: Sender<FromServerEvent>,
    _tx_in: Sender<PayloadEvent>, //TODO: verify that this can be removed
    tx2_in: UnboundedSender<UpgradedPeerData>,
    validator_list: Vec<String>,
    notify: Arc<Notify>,
    root_hash: String,
    public: EcdsaPublicKey,
    secret: EcdsaPrivateKey,
) -> Result<(), std::io::Error> {
    const PEER_MESSAGE_MAX_LEN: usize = 248;
    let total_other_peers = validator_list.len() - 1;

    // create listening server and register it will poll to receive events
    let (socket, port) = get_udp_and_addr().await;
    let sender = tx_out.clone();
    // spawn thread to not make Arc become mad
    let p = port.clone();
    tokio::spawn(async move {
        let host_port_msg = FromServerEvent::HostSocket(p);
        // inform the peer loop about where the server backend listens to
        let _ = sender.send(host_port_msg).await;
    });

    // peers registered in initial discovery mode
    let mut registered_peers: Vec<String> = Vec::new();
    // peers upgraded to commynicate with server handle
    let mut upgraded_peers: HashMap<u8, EcdsaPublicKey> = HashMap::new();
    // peers with synchronized root hash
    let mut sync_hash_peers: Vec<EcdsaPublicKey> = Vec::new();
    // when all peers have been registered
    let mut registry_done = false;
    // when all peers have been upgraded
    let mut upgrade_done = false;
    // when all peers have the same initial root hash
    let mut root_hash_confirmed = false;

    // Public key mapped to short ID: usize -> String
    let short_id_to_hex_key = Arc::new(Mutex::new(HashMap::<usize, EcdsaPublicKey>::new()));

    notify.notify_one();

    let tx_ug = tx2_in.clone();
    let mut nonce: usize = 0;
    let rhc = root_hash.clone();
    loop {
        let root_hash = rhc.clone();
        let mut buf = [0; PEER_MESSAGE_MAX_LEN];
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
                let in_upgraded_list = upgraded_peers.values().any(|x| *x == peer_key_type);
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
                    let arc = short_id_to_hex_key.clone();
                    let mut inner = arc.lock().await;
                    inner.insert(nonce, peer_key_type);
                    log::debug!("register peer with id {} as seen", nonce);
                    registry_done = registered_peers.len() == total_other_peers;
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
                    upgraded_peers.insert(peer_id, peer_key_type);
                    upgrade_done = upgraded_peers.len() == total_other_peers;
                    log::debug!(
                        "upgrades done: {}/{}",
                        upgraded_peers.len(),
                        total_other_peers,
                    );
                    continue;
                } else {
                    log::error!("upgrade ACK message rejected, discard");
                }
                continue;
            }
            let (is_valid, peer_id) = is_root_hash_tag(buf.to_vec());
            if !is_valid {
                log::error!("waiting for root message");
                continue;
            } else if !root_hash_confirmed {
                let arc = short_id_to_hex_key.clone();
                let inner = arc.lock().await;
                let peer_id = peer_id as usize;
                let key = match inner.get(&peer_id) {
                    Some(k) => k.clone(),
                    None => {
                        log::error!("cannot find peer as upgraded, skip");
                        continue;
                    }
                };
                let in_root_list = sync_hash_peers.contains(&key);
                let (ok, _id) = verify_root_hash_sync_message(buf.to_vec(), root_hash, key.clone());
                if ok && !in_root_list {
                    sync_hash_peers.push(key.clone());
                    log::debug!(
                        "root hash synched: {}/{}",
                        sync_hash_peers.len(),
                        total_other_peers,
                    );
                }
                root_hash_confirmed = sync_hash_peers.len() == total_other_peers;
                if root_hash_confirmed {
                    tokio::spawn(async move {
                        let _ = server_consensus_loop(port, upgraded_peers, public, secret).await;
                    });
                    // exit this loop and only serv consensus messages from now on
                    break;
                }
            }
        } else if root_hash_confirmed {
            log::debug!("waiting for consensus message..");
        }
    }

    Ok(())
}

async fn server_consensus_loop(
    serv_port: String,
    ug_peers: HashMap<u8, EcdsaPublicKey>,
    public: EcdsaPublicKey,
    secret: EcdsaPrivateKey,
) -> Result<(), std::io::Error> {
    let mut addr = "127.0.0.1:".to_string();
    addr.push_str(&serv_port);
    let socket = UdpSocket::bind(addr).await.unwrap();
    let mut messages = Vec::<Vec<u8>>::new();
    let mut buf = [0; 250];
    let (tx, mut rx): (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) =
        mpsc::unbounded_channel();
    let message_worker = MessageWorker::new(ug_peers, secret, public);

    let m = message_worker.clone();
    tokio::spawn(async move {
        loop {
            let bytes_recv = match socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => continue,
            };
            // uh, let's circle back on this exact value a bit later (TODO)
            if bytes_recv > 200 {
                let v = buf.to_vec();
                match m.validate_received(v.clone()) {
                    Ok(_) => {
                        let _ = tx.send(v);
                    }
                    Err(e) => {
                        log::error!("{}", e);
                        continue;
                    }
                }
            }
        }
    });

    loop {
        while let Some(msg) = rx.recv().await {
            messages.push(msg);
        }
    }
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

#[allow(unused)]
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
