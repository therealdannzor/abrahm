// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/ in
// combination with https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs
#![allow(unused)]

use futures::{FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::{collections::HashMap, sync::Arc, vec::Vec};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;

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
    pub channel: Option<mpsc::UnboundedSender<std::result::Result<Message, Error>>>,
}

pub type Result<T> = std::result::Result<T, Rejection>;

pub type Peers = Arc<RwLock<HashMap<String, Peer>>>;

#[derive(Serialize, Deserialize, Debug)]
pub struct TopicsRequest {
    topics: Vec<String>,
}

pub async fn connect_peer(ws: WebSocket, id: String, mut single_peer: Peer, peers: Peers) {
    // socket sender and receiver
    let (peer_ws_sender, mut peer_ws_recv) = ws.split();

    // handle buffering and flushing of messages to the socket
    let (tx, rx) = mpsc::unbounded_channel();
    let rx = UnboundedReceiverStream::new(rx);
    tokio::task::spawn(rx.forward(peer_ws_sender).map(|result| {
        if let Err(e) = result {
            eprintln!("error sending ws message: {}", e);
        }
    }));

    single_peer.channel = Some(tx);
    peers.write().await.insert(id.clone(), single_peer);
    log::debug!("peer {} connected", id);

    while let Some(result) = peer_ws_recv.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("error receiving ws message for id {}: {}", id.clone(), e);
                break;
            }
        };
        peer_msg(&id, msg, &peers).await;
    }
    peers.write().await.remove(&id);
    log::debug!("{} disconnected", id);
}

async fn peer_msg(id: &str, msg: Message, peers: &Peers) {
    log::debug!("received message from: {}: {:?}", id, msg);
    let message = match msg.to_str() {
        Ok(v) => v,
        Err(_) => return,
    };

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

    let mut locked = peers.write().await;
    if let Some(v) = locked.get_mut(id) {
        v.gossip_msg = tp_req.topics;
    }
}
