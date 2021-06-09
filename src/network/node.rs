#![allow(unused)]

use std::collections::HashMap;
use std::io::prelude::*;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{
    mpsc::{Receiver, Sender},
    Arc, RwLock,
};
use std::thread::spawn;
use std::vec::Vec;

pub struct Node {
    // The operator and owner of any funds related to this node
    author: String,
    // Listening URL
    listen_port: u16,
    // The active and inactive connections this node is connnected to
    connections: Arc<RwLock<HashMap<String, TcpStream>>>,
    // Messages received
    message_buf: Arc<RwLock<Vec<String>>>,
    // Channel to send messages
    tx: Sender<String>,
    // Channel to receive messages
    rx: Receiver<String>,
}

impl Node {
    pub fn new(author: String, listen_port: u16) -> Self {
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        Self {
            author,
            listen_port,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_buf: Arc::new(RwLock::new(Vec::new())),
            tx,
            rx,
        }
    }

    pub fn listen(&self, fallback_port: u16) {
        let addrs = [
            SocketAddr::from(([127, 0, 0, 1], self.listen_port)),
            SocketAddr::from(([127, 0, 0, 1], fallback_port)), // fallback port if the primary `listen_port` fails
        ];
        let listener = TcpListener::bind(&addrs[..]).expect("could not listen on this URL");
    }

    pub fn poll_message(self) {
        let arcw = self.message_buf.clone();
        spawn(move || {
            let msg = self.rx.recv();
            let msg = match msg {
                Ok(_) => msg.unwrap(),
                Err(_) => panic!("error polling for new messages"),
            };
            {
                let mut arcw = arcw.write().unwrap();
                arcw.push(msg);
            }
        });
    }

    pub fn send_message(&mut self, data: String) {
        let transmit = self.tx.clone();
        spawn(move || {
            transmit.send(data);
        });
    }

    pub fn num_peers(self) -> usize {
        self.connections.read().unwrap().len()
    }

    pub fn connect(self, mut stream: TcpStream, url: String) {
        if let Ok(stream) = TcpStream::connect(url) {
            let arcw = self.connections.clone().write().unwrap();
            arcw.insert(id, stream);
        } else {
            log::error!("could not establish connection with peer");
        }
    }
}
