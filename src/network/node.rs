#![allow(unused)]

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

pub struct Node {
    // Enumerate peers encountered. Local ID is always 0.
    id: usize,
    // The operator and owner of any funds related to this node
    author: String,
    // Listening URL
    listen_port: u16,
    // The active and inactive connections this node is connnected to
    connections: Arc<RwLock<HashMap<usize, TcpStream>>>,
}

impl Node {
    pub fn new(author: String, listen_port: u16) -> Self {
        Self {
            id: 0,
            author,
            listen_port,
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn serve(&self, fallback_port: u16) {
        let addrs = [
            SocketAddr::from(([127, 0, 0, 1], self.listen_port)),
            SocketAddr::from(([127, 0, 0, 1], fallback_port)), // fallback port
        ];
        let listener = TcpListener::bind(&addrs[..]).expect("could not listen on this URL");
    }
}
