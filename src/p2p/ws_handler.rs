// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/
#![allow(unused)]
use super::ws_peer::{Peer, Peers, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::{http::StatusCode, reply::json, ws::Ws, Reply};

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterRequest {
    user_id: usize,
    message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterResponse {
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
pub struct Event {
    user_id: Option<usize>,
    uuid: String,

    // message is a new block event
    message: String,
}

pub async fn health() -> Result<impl Reply> {
    Ok(StatusCode::OK)
}

pub async fn get_peer_info(ws: Ws, id: String, peers: Peers) -> Result<impl Reply> {
    let mut map = peers.lock().unwrap();
    let mut result: Vec<String> = vec![];
    if map.contains_key(&id) {
        result = map.get_mut(&id).unwrap().gossip_msg.clone();
    }

    Ok(json(&result))
}

pub async fn unregister(id: String, peers: Peers) -> Result<impl Reply> {
    //peers.lock().write().await.remove(&id);
    Ok(StatusCode::OK)
}

async fn register_client(id: String, user_id: usize, peers: Peers) {
    let id = id.replace("\"", "");
    peers.lock().unwrap().insert(
        id,
        Peer {
            user_id,
            gossip_msg: std::vec::Vec::new(),
            channel: None,
        },
    );
}

pub async fn register(body: RegisterRequest, peers: Peers) -> Result<impl Reply> {
    let user_id = body.user_id;
    let uuid = Uuid::new_v4().simple().to_string();

    register_client(uuid.clone(), user_id, peers).await;
    Ok(json(&RegisterResponse { uuid }))
}

pub async fn publish(body: Event, peers: Peers) -> Result<impl Reply> {
    let peer_uuid = body.uuid.clone();
    let peer_uuid = peer_uuid.replace("\"", "");
    let uuid_cpy = peer_uuid.clone();
    let new_message = body.message.clone();

    let mut map = peers.lock().unwrap();
    if map.contains_key(&peer_uuid) {
        map.get_mut(&peer_uuid)
            .unwrap()
            .gossip_msg
            .push(new_message);
    } else {
        println!("couldn't find key: {}", peer_uuid);
    }

    let new_msg_state = map.get_mut(&uuid_cpy).unwrap().gossip_msg.clone();

    Ok(json(&new_msg_state))
}
