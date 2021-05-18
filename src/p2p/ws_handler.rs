// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/
#![allow(unused)]
use super::ws_peer::{Peer, Peers, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec::Vec;
use uuid::Uuid;
use warp::{http::StatusCode, reply::json, ws::Ws, Filter, Reply};

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterResponse {
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    // easy identifier
    user_id: usize,

    // consensus messages
    phase: String,
    view: u32,
    round: u32,
}

impl Event {
    pub fn new(user_id: usize, phase: String, view: u32, round: u32) -> Self {
        Self {
            user_id,
            phase,
            view,
            round,
        }
    }
}

enum MessageType {
    Preprepare,
    Prepare,
    Commit,
}

// returns stored consensus messages from other peers
pub async fn messagestore(
    ws: Ws,
    peers: Peers,
    param_tail: warp::path::Tail,
) -> Result<impl Reply> {
    let params: Vec<&str> = param_tail.as_str().split('/').collect();
    if params.len() != 2 {
        warp::reject();
    }

    let message_type = params[0];
    let target_id = params[1];
    let target_id = target_id.parse::<usize>().unwrap();
    let mut p = peers.lock().unwrap();
    let mut res: &Vec<String> = &vec![String::from("")];
    match message_type {
        "preprepare" => res = p.preprepare_msg.get_mut(&target_id).unwrap(),
        "prepare" => res = p.prepare_msg.get_mut(&target_id).unwrap(),
        "commit" => res = p.commit_msg.get_mut(&target_id).unwrap(),
        _ => log::info!("invalid consensus message"),
    }

    Ok(json(&res))
}

pub async fn register(body: Event, peers: Peers) -> Result<impl Reply> {
    let target_id = body.user_id;
    let mut p = peers.lock().unwrap();

    if !p.preprepare_msg.contains_key(&target_id) {
        p.preprepare_msg.insert(target_id, Vec::new());
    }
    if !p.prepare_msg.contains_key(&target_id) {
        p.prepare_msg.insert(target_id, Vec::new());
    }
    if !p.commit_msg.contains_key(&target_id) {
        p.commit_msg.insert(target_id, Vec::new());
    }

    Ok(json(&body))
}

pub async fn publish(body: Event, peers: Peers) -> Result<impl Reply> {
    let target_id = body.user_id;
    let message_type = body.phase.clone();
    let message_type = message_type.as_str();

    let mut p = peers.lock().unwrap();
    let msg = serde_json::to_string(&body).unwrap();
    match message_type {
        "preprepare" => {
            if p.preprepare_msg.contains_key(&target_id) {
                p.preprepare_msg.get_mut(&target_id).unwrap().push(msg);
            }
        }
        "prepare" => {
            if p.prepare_msg.contains_key(&target_id) {
                p.prepare_msg.get_mut(&target_id).unwrap().push(msg);
            }
        }
        "commit" => {
            if p.commit_msg.contains_key(&target_id) {
                p.commit_msg.get_mut(&target_id).unwrap().push(msg);
            }
        }
        _ => log::info!("invalid consensus message"),
    }

    Ok(json(&body))
}
