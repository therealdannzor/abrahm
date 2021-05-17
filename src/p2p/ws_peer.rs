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
    // Local identifier
    pub user_id: usize,

    // Collection of consensus messages buffered from other peers. The maps are from user_id to the
    // buffered set of messages. Each message has the form:
    // '{"user_id": <usize>, "view": <usize>, "digest": <String>}'
    //
    // TODO: find a better solution to avoid needing separate maps for each connected peer.
    pub preprepare_msg: HashMap<usize, Vec<String>>,
    pub prepare_msg: HashMap<usize, Vec<String>>,
    pub commit_msg: HashMap<usize, Vec<String>>,

    // Conduit to reach this peer
    pub channel: Option<UnboundedSender<std::result::Result<Message, Error>>>,
}

pub type Result<T> = std::result::Result<T, Rejection>;

pub type Peers = Arc<Mutex<Peer>>;

#[derive(Serialize, Deserialize, Debug)]
pub struct TopicsRequest {
    topics: Vec<String>,
}
