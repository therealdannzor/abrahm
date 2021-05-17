// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/
#![allow(unused)]
use super::ws_peer::{Peer, Peers, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec::Vec;
use uuid::Uuid;
use warp::{http::StatusCode, reply::json, ws::Ws, Filter, Reply};

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
    // easy identifier
    user_id: Option<usize>,

    // consensus messages
    view: u32,
    round: u32,
    author_uuid: String, // websocket id used as validator address
}

enum MessageType {
    Preprepare,
    Prepare,
    Commit,
}

pub async fn health() -> Result<impl Reply> {
    Ok(StatusCode::OK)
}

// returns stored consensus messages from other peers
pub async fn messagestore(
    ws: Ws,
    peers: Peers,
    param_tail: warp::path::Tail,
) -> Result<impl Reply> {
    let params: Vec<&str> = param_tail.as_str().split('/').collect();
    if params.len() != 2 {
        Err(warp::reject());
    }

    let client_id = params[0];
    let target_id = params[1];
    let mut map = peers.lock().unwrap();
    let mut p: Peer;
    if map.contains_key(&client_id) {
        let mut result: Vec<String> = vec![];
        result = map
            .get_mut(&id)
            .unwrap()
            .clone()
            .preprepare_msg
            .clone()
            .get_mut(&target_id)
            .unwrap()
            .clone();

        Ok(json(&result))
    } else {
        Err(warp::reject())
    }
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
            preprepare_msg: HashMap::new(),
            prepare_msg: HashMap::new(),
            commit_msg: HashMap::new(),
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
    let peer_uuid = body.author_uuid.clone();
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
