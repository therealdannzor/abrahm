#![allow(unused)]

use super::client_handle::ClientHandle;
use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use std::{
    collections::{HashMap, VecDeque},
    default::Default,
    io,
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::from_utf8,
};
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

// InboundMessage holds the different message types which are sent to the server.
// This includes both events from clients connecting but also internal events.
pub enum InboundMessage {
    OpenPort { response: oneshot::Sender<u16> },

    NewClient(EcdsaPublicKey, TcpListener, oneshot::Sender<Token>),
    ClientMessage(Token, Vec<u8>),
    ErrorMessage(io::Error),
}

#[derive(Default, Debug)]
struct ConnData {
    clients: HashMap<Token, ClientHandle>,
    streams: HashMap<Token, TcpStream>,
}

impl ConnData {
    fn new() -> Self {
        Self {
            clients: Default::default(),
            streams: Default::default(),
        }
    }
    fn insert_stream(mut self, token: Token, stream: TcpStream) {
        self.streams.insert(token, stream);
    }
}

pub struct ServerHandle {
    tx: Sender<InboundMessage>,
}

impl ServerHandle {
    pub fn new(tx: Sender<InboundMessage>) -> Self {
        Self { tx }
    }

    pub async fn expose_port(&self) -> Option<u16> {
        let (send, receive) = oneshot::channel();
        let msg = InboundMessage::OpenPort { response: send };
        if self.tx.send(msg).await.is_err() {
            return None;
        }
        Some(receive.await.unwrap())
    }

    pub async fn new_client(
        &self,
        key: EcdsaPublicKey,
        listener: TcpListener,
    ) -> Result<Token, io::Error> {
        let (send, receive) = oneshot::channel();
        let msg = InboundMessage::NewClient(key, listener, send);
        if self.tx.send(msg).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "new client send message field",
            ));
        }
        Ok(receive.await.unwrap())
    }
}

pub fn spawn_event_listener() -> (ServerHandle, JoinHandle<()>) {
    let (send, recv) = channel(32);
    let handle = ServerHandle::new(send);
    let join = tokio::spawn(async move {
        let res = match event_loop(recv).await {
            Ok(()) => {}
            Err(e) => {
                panic!("event loop failed: {:?}", e);
            }
        };
    });

    (handle, join)
}

const PEER_TOKEN: Token = Token(0);

async fn event_loop(mut recv: Receiver<InboundMessage>) -> Result<(), io::Error> {
    let mut unique_token = Token(PEER_TOKEN.0 + 1);
    let mut data = ConnData::default();
    let mut poller = match Poll::new() {
        Ok(poll) => poll,
        Err(e) => panic!("failed to create poll: {:?}", e),
    };
    let mut mailbox = VecDeque::new();
    let mut listen_port: Option<u16> = None;

    while let Some(msg) = recv.recv().await {
        match msg {
            InboundMessage::NewClient(pk, stream, response) => {
                info!("new peer encountered");
                let (mut conn, addr) = match stream.accept() {
                    Ok((conn, addr)) => (conn, addr),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => panic!("unexpected event error: {:?}", e),
                };
                info!("socket accepted connection from: {}", addr);
                let token = next_token(&mut unique_token);
                poller.registry().register(
                    &mut conn,
                    token,
                    Interest::READABLE.add(Interest::WRITABLE),
                );

                data.streams.insert(token, conn);

                let _ = response.send(token);
            }
            InboundMessage::ClientMessage(token, msg) => {
                let mut stream = match data.streams.get_mut(&token) {
                    Some(s) => s,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "client message missing token",
                        ));
                    }
                };
                if msg.len() > 0 {
                    write_stream_data(&mut stream, &msg);
                } else {
                    // we do not have a message, so we process received messages
                    read_stream_data(&mut stream, &mut mailbox);
                }
            }
            InboundMessage::OpenPort { response } => {
                // if we have already opened a port, return the existing listen port
                if listen_port.is_some() {
                    let _ = response.send(listen_port.unwrap());
                    continue;
                }

                let listener = open_socket();
                let port = listener.local_addr().unwrap().port();
                listen_port = Some(port);

                let _ = response.send(port);
            }
            InboundMessage::ErrorMessage(e) => {
                log::info!("error: {:?}", e.into_inner());
            }
            _ => {
                log::info!("unreachable arm, this should not happen");
            }
        }
    }

    Ok(())
}

fn open_socket() -> TcpListener {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let socket = SocketAddr::new(loopback, /* dynamically allocate */ 0);

    let mut srv = match TcpListener::bind(socket) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    srv
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
fn check_bytes_read(mut amount: usize, recv: &mut Vec<u8>) -> Option<&[u8]> {
    if amount != 0 {
        let recv = &recv[..amount];
        if let Ok(buf) = from_utf8(recv) {
            let trimmed = buf.trim_end();
            info!("received data: {}", buf.trim_end());
            Some(recv)
        } else {
            info!("received (non utf-8) data: {:?}", recv);
            None
        }
    } else {
        None
    }
}

fn write_stream_data(connection: &mut TcpStream, data: &[u8]) -> io::Result<bool> {
    match connection.write(data) {
        Ok(n) if n < data.len() => return Err(io::ErrorKind::WriteZero.into()),
        Ok(_) => {
            return Ok(true);
        }
        // We are not ready yet
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            return Ok(false);
        }
        // We can work around this by trying again
        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
            return write_stream_data(connection, data)
        }
        // Unexpected errors that are undesired
        Err(e) => return Err(e),
    }
}

fn read_stream_data(
    connection: &mut TcpStream,
    mailbox: &mut VecDeque<Vec<u8>>,
) -> io::Result<bool> {
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
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let octs = check_bytes_read(bytes_read, &mut rcv_dat);
    if octs.is_none() {
        return Ok(false);
    } else {
        mailbox.push_back(octs.unwrap().to_vec());
    }

    if conn_closed {
        info!("connection closed");
    }
    Ok(true)
}
