#![allow(unused)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::mpsc;
use std::sync::{
    atomic::AtomicBool,
    mpsc::{Receiver, Sender},
    Arc, RwLock,
};
use std::thread::spawn;
use std::vec::Vec;

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};

// Node is the highest abstraction for node-to-node communication on the network
pub struct Node {
    // The operator and owner of any funds related to this node
    author: String,
    // Handler for TCP connections
    handler: TcpHandler,
}
impl Node {
    pub fn new(author: String, stream_cap: usize) -> Self {
        Self {
            author,
            handler: TcpHandler::new(stream_cap),
        }
    }
}

// TargetSocket encapsulates information on other hosts this client communicates with
struct TargetSocket {
    socket_addr: SocketAddr,
    stream: TcpStream,
}
impl TargetSocket {
    fn new(socket_addr: SocketAddr, stream: TcpStream) -> Self {
        Self {
            socket_addr,
            stream,
        }
    }
    fn port(self) -> u16 {
        self.socket_addr.port()
    }
    fn ip(self) -> IpAddr {
        self.socket_addr.ip()
    }
}

// TcpHandler handles the TCP communication between nodes
struct TcpHandler {
    // Poller of new events
    p: Poll,

    // Store events
    event_store: Events,

    // Map of `Token` (unique identifiers) -> `TcpStream`
    map: HashMap<Token, TargetSocket>,

    // If the handler is currently listening to a socket
    listening: bool,

    // Port number, only when it is listening
    port: Option<u16>,

    // Transmit messages internally to the handler
    send_tx: Sender<Vec<u8>>,

    // Pull messages for the handler to dispatch
    send_rx: Receiver<Vec<u8>>,

    // Exit loop signal
    atomic: AtomicBool,
}

const PEER_CONN_TKN: Token = Token(0);

impl TcpHandler {
    fn queue_data_to_send(self, data: &'static [u8]) -> std::io::Result<bool> {
        let tx = self.send_tx.clone();
        spawn(move || {
            tx.send(data.to_vec());
        });
        Ok(true)
    }

    fn new(event_capacity: usize) -> Self {
        let (send_tx, send_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        Self {
            p: Poll::new().unwrap(),
            event_store: Events::with_capacity(event_capacity),
            map: HashMap::new(),
            listening: false,
            port: None,
            send_tx,
            send_rx,
            atomic: AtomicBool::new(false),
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
    // 1. encounter new connection: register its token -> address in the hashmap
    // 2. handle known connection: pass the data to a handler
    fn event_listener(mut self, srv: TcpListener) -> std::io::Result<()> {
        let mut uniq_tkn = Token(PEER_CONN_TKN.0 + 1);

        loop {
            if *self.atomic.get_mut() {
                log::info!("event listener stopped: exit signal received");
                return Ok(());
            }
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

                        let ts = TargetSocket::new(addr, conn);
                        self.map.insert(token, ts);
                    },
                    token => {
                        let done = if let Some(ts) = self.map.get_mut(&token) {
                            let msg = match self.send_rx.try_recv() {
                                Ok(msg) => Some(msg),
                                Err(_) => None,
                            };
                            handle_conn_event(self.p.registry(), &mut ts.stream, event, msg)?
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

    pub fn num_peers(self) -> usize {
        self.map.len()
    }
}

fn handle_conn_event(
    registry: &Registry,
    connection: &mut TcpStream,
    event: &Event,
    data: Option<Vec<u8>>,
) -> std::io::Result<bool> {
    if event.is_writable() {
        write_stream_data(registry, connection, event, data)?;
    }

    if event.is_readable() {
        let mut conn_closed = false;
        let mut rcv_dat = vec![0, 255];
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

        check_bytes_read(bytes_read, &mut rcv_dat);

        if conn_closed {
            log::info!("connection closed");
            return Ok(true);
        }
    }

    Ok(false)
}

// Updates the token to make sure we have unique ones for each stream.
fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

// Checks our receive buffer whether there is something to read.
// If this is true, we remove it from the buffer and log it to the user.
// If this is false, we do nothing.
fn check_bytes_read(mut amount: usize, recv: &mut Vec<u8>) {
    if amount != 0 {
        let recv = &recv[..amount];
        if let Ok(buf) = from_utf8(recv) {
            log::info!("received data: {}", buf.trim_end());
        } else {
            log::info!("received (non utf-8) data: {:?}", recv);
        }
    }
}

fn write_stream_data(
    registry: &Registry,
    connection: &mut TcpStream,
    event: &Event,
    data: Option<Vec<u8>>,
) -> std::io::Result<bool> {
    let data: &[u8] = &data.unwrap()[..];
    match connection.write(data) {
        Ok(n) if n < data.len() => return Err(std::io::ErrorKind::WriteZero.into()),
        Ok(_) => {
            registry.reregister(connection, event.token(), Interest::READABLE)?;
            return Ok(true);
        }
        // We are not ready yet
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Ok(false);
        }
        // We can work around this by trying again
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
            return write_stream_data(registry, connection, event, Some(data.to_vec()))
        }
        // Unexpected errors that are undesired
        Err(e) => return Err(e),
    }
}
