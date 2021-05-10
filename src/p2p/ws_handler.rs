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

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    peer_id: usize,
    topic: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterResponse {
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
pub struct Event {
    // user_id is provided when an event message is unicast to
    // a particular peer in the network
    peer_id: Option<usize>,
    // topic of the event
    topic: String,
    // message is the payload of the event
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

async fn register_client(id: String, peer_id: usize, topic: String, peers: Peers) {
    peers.write().await.insert(
        id,
        Peer {
            id: peer_id,
            topic_list: vec![topic],
            channel: None,
        },
    );
}

pub async fn register(body: RegisterRequest, peers: Peers) -> Result<impl Reply> {
    let peer_id = body.peer_id;
    let peer_topic = body.topic;
    let uuid = Uuid::new_v4().simple().to_string();

    register_client(uuid.clone(), peer_id, peer_topic, peers).await;
    Ok(json(&RegisterResponse { uuid }))
}

pub async fn publish(body: Event, peers: Peers) -> Result<impl Reply> {
    peers
        .read()
        .await
        .iter()
        .filter(|(_, peer)| match body.peer_id {
            Some(v) => peer.id == v,
            None => true,
        })
        .filter(|(_, peer)| peer.topic_list.contains(&body.topic))
        .for_each(|(_, peer)| {
            if let Some(sender) = &peer.channel {
                let _ = sender.send(Ok(Message::text(body.message.clone())));
            }
        });

    Ok(StatusCode::OK)
}
