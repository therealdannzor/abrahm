// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/ in
// combination with https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    vec::Vec,
};
use tokio::sync::mpsc::UnboundedSender;

use warp::{ws::Message, Error, Rejection};
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
