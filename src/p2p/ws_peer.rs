// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/ in
// combination with https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs
#![allow(unused)]

use futures::{FutureExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    vec::Vec,
};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    RwLock,
};

use warp::{
    ws::{Message, WebSocket},
    Error, Rejection,
};

#[derive(Debug, Clone)]
pub struct Peer {
    // peer identifier
    pub user_id: usize,
    // list of messages this peer has received
    pub gossip_msg: Vec<String>,
    // channel to this peer
    pub channel: Option<UnboundedSender<std::result::Result<Message, Error>>>,
}

pub type Result<T> = std::result::Result<T, Rejection>;

pub type Peers = Arc<Mutex<HashMap<String, Peer>>>;

#[derive(Serialize, Deserialize, Debug)]
pub struct TopicsRequest {
    topics: Vec<String>,
}

pub async fn get_peer_messages(
    ws: WebSocket,
    id: String,
    mut single_peer: Peer,
    peers: Peers,
) -> Result<Value> {
    Ok(serde_json::json!({ "user_id": 10, "message": "Blockz0r"}))
}

async fn peer_msg(id: &str, msg: Message, peers: &Peers) {
    println!("==== peer_msg received msg from: {}: {:?}", id, msg);
    let message = match msg.to_str() {
        Ok(v) => v,
        Err(_) => return,
    };

    println!("==== peer_msg parsed msg: {}: {:?}", id, msg);
    if message == "ping" || message == "ping\n" {
        return;
    }

    let tp_req: TopicsRequest = match from_str(&message) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error message parsing to topics: {}", e);
            return;
        }
    };

    //let mut locked = peers.write().await;
    //if let Some(v) = locked.get_mut(id) {
    //v.gossip_msg = tp_req.topics;
    //println!("==== peer_mg with v.gossip_msg: {:?}", v.gossip_msg);
    //}
}
