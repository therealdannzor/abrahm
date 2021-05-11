// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/
#![allow(unused)]

use super::ws_peer::{connect_peer, Peer, Peers, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::{
    http::StatusCode,
    reply::json,
    ws::{Message, Ws},
    Reply,
};

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
    // user_id is provided when an event message is unicast to
    // a particular peer in the network
    user_id: Option<usize>,
    // message is a new block event
    message: String,
}

pub async fn health() -> Result<impl Reply> {
    Ok(StatusCode::OK)
}

pub async fn get_peer_info(ws: Ws, id: String, peers: Peers) -> Result<impl Reply> {
    let peer = peers.read().await.get(&id).cloned();
    match peer {
        Some(c) => Ok(ws.on_upgrade(move |socket| connect_peer(socket, id, c, peers))),
        None => Err(warp::reject::not_found()),
    }
}

pub async fn unregister(id: String, peers: Peers) -> Result<impl Reply> {
    peers.write().await.remove(&id);
    Ok(StatusCode::OK)
}

async fn register_client(id: String, user_id: usize, peers: Peers) {
    peers.write().await.insert(
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
    let peer_number = body.user_id;
    peers
        .read()
        .await
        .iter()
        .filter(|(_, p)| match peer_number {
            Some(v) => p.user_id == v,
            None => true,
        })
        .for_each(|(_, p)| {
            if let Some(sender) = &p.channel {
                let _ = sender.send(Ok(Message::text(body.message.clone())));
            }
        });

    let sender_id = vec![peer_number];
    Ok(json(&sender_id))
}
