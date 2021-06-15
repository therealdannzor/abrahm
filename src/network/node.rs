#![allow(unused)]

use std::collections::HashMap;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::mpsc;
use std::sync::{
    mpsc::{Receiver, Sender},
    Arc, RwLock,
};
use std::thread::spawn;
use std::vec::Vec;

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};

pub struct Node {
    // The operator and owner of any funds related to this node
    author: String,
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
    pub fn new(author: String) -> Self {
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        Self {
            author,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_buf: Arc::new(RwLock::new(Vec::new())),
            tx,
            rx,
        }
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
}

struct TcpHandler {
    // Poller of new events
    p: Poll,

    // Store events
    event_store: Events,

    // Map of `Token` (unique identifiers) -> `TcpStream`
    map: HashMap<Token, TcpStream>,

    // If the handler is currently listening to a socket
    listening: bool,

    // Port number, only when it is listening
    port: Option<u16>,
}

const PEER_CONN_TKN: Token = Token(0);

impl TcpHandler {
    fn new(event_capacity: usize) -> Self {
        Self {
            p: Poll::new().unwrap(),
            event_store: Events::with_capacity(event_capacity),
            map: HashMap::new(),
            listening: false,
            port: None,
        }
    }

    // open_socket does two things:
    //
    // 1. listens to an available port on localhost and changes the state of TcpHandler to
    //    `listening` and its `port` to a Some value.
    // 2. registers event sources with the poll instance through an array of `Token`s to identify
    //    the different types of events to listen for.
    fn open_socket(&mut self) -> TcpListener {
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let socket = SocketAddr::new(loopback, /* dynamically allocate */ 0);

        let mut srv = match TcpListener::bind(socket) {
            Ok(s) => s,
            Err(e) => panic!("could not bind socket, error: {:?}", e),
        };
        self.listening = true;
        self.port = Some(srv.local_addr().unwrap().port());

        self.p
            .registry()
            .register(&mut srv, PEER_CONN_TKN, Interest::READABLE);

        srv
    }

    // event_listener reacts to the two events:
    //
    // 1. new peer connecting: register its token -> address in the hashmap
    // 2. handle connection: pass the data to a handler
    fn event_listener(mut self, srv: TcpListener) -> std::io::Result<()> {
        let mut uniq_tkn = Token(PEER_CONN_TKN.0 + 1);

        loop {
            match self.p.poll(&mut self.event_store, None) {
                Ok(ok) => (),
                Err(e) => panic!("could not poll events, {:?}", e),
            };

            for event in self.event_store.iter().clone() {
                match event.token() {
                    PEER_CONN_TKN => loop {
                        let (mut conn, addr) = match srv.accept() {
                            Ok((conn, addr)) => (conn, addr),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => panic!("unexpected event error: {:?}", e),
                        };

                        log::info!("socket accepted connection from: {}", addr);
                        let token = next_token(&mut uniq_tkn);
                        self.p.registry().register(
                            &mut conn,
                            token,
                            Interest::READABLE.add(Interest::WRITABLE),
                        );
                        self.map.insert(token, conn);
                    },
                    token => {
                        let done = if let Some(conn) = self.map.get_mut(&token) {
                            handle_conn_event(self.p.registry(), conn, event, data)?
                        } else {
                            false
                        };
                        if done {
                            self.map.remove(&token);
                        }
                    }
                }
            }
        }
    }
}

fn handle_conn_event(
    registry: &Registry,
    connection: &mut TcpStream,
    event: &Event,
    data: &[u8],
) -> std::io::Result<bool> {
    if event.is_writable() {
        match connection.write(data) {
            Ok(n) if n < data.len() => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(_) => registry.reregister(connection, event.token(), Interest::READABLE)?,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                return handle_conn_event(registry, connection, event, data)
            }
            Err(e) => return Err(e),
        }
    }

    if event.is_readable() {
        let mut conn_closed = false;
        let mut rcv_dat = vec![0, 4096];
        let mut bytes_read = 0;
        loop {
            match connection.read(&mut rcv_dat[bytes_read..]) {
                Ok(0) => {
                    conn_closed = true;
                    break;
                }
                Ok(n) => {
                    bytes_read += n;
                    if bytes_read == rcv_dat.len() {
                        rcv_dat.resize(rcv_dat.len() + 1024, 0);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if bytes_read != 0 {
            let rcv_dat = &rcv_dat[..bytes_read];
            if let Ok(buf) = from_utf8(rcv_dat) {
                log::info!("received data: {}", buf.trim_end());
            } else {
                log::info!("received (non UTF-8) data: {:?}", rcv_dat);
            }
        }

        if conn_closed {
            log::info!("connection closed");
            return Ok(true);
        }
    }

    Ok(false)
}

fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}
