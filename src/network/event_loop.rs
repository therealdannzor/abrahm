#![allow(unused)]

use super::client_handle::ClientHandle;
use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use std::collections::{HashMap, VecDeque};
use std::default::Default;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::from_utf8;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::Receiver;

pub enum ServerMessage {
    NewClient(EcdsaPublicKey, TcpListener),
    ClientMessage(EcdsaPublicKey, Vec<u8>),
    ErrorMessage(std::io::Error),
}

#[derive(Default, Debug)]
struct ConnData {
    clients: HashMap<EcdsaPublicKey, ClientMetadata>,
}

#[derive(Debug)]
struct ClientMetadata {
    stream: TcpStream,
    token: Token,
}
impl ClientMetadata {
    pub fn new(stream: TcpStream, token: Token) -> Self {
        Self { stream, token }
    }

    fn tcp(&self) -> TcpStream {
        self.stream
    }
}

const PEER_TOKEN: Token = Token(0);

async fn event_listener(mut recv: Receiver<ServerMessage>) {
    let mut unique_token = Token(PEER_TOKEN.0 + 1);
    let mut data = ConnData::default();
    let mut poller = match Poll::new() {
        Ok(poll) => poll,
        Err(e) => panic!("failed to create poll: {:?}", e),
    };
    let mut mailbox = VecDeque::new();

    while let Some(msg) = recv.recv().await {
        match msg {
            ServerMessage::NewClient(pk, stream) => {
                info!("new peer encountered");
                let (mut conn, addr) = match stream.accept() {
                    Ok((conn, addr)) => (conn, addr),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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

                let client_dat = ClientMetadata::new(conn, token);
                data.clients.insert(pk, client_dat);
            }
            ServerMessage::ClientMessage(pk, msg) => {
                let mut stream = data.clients.get(&pk).unwrap().tcp();
                if msg.len() > 0 {
                    write_stream_data(&mut stream, &msg);
                } else {
                    // we do not have a message, so we process received messages
                    read_stream_data(&mut stream, &mut mailbox);
                }
            }
            ServerMessage::ErrorMessage(e) => {
                log::info!("error: {:?}", e.into_inner());
            }
            _ => {
                log::info!("unreachable arm, this should not happen");
            }
        }
    }
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

fn write_stream_data(connection: &mut TcpStream, data: &[u8]) -> std::io::Result<bool> {
    match connection.write(data) {
        Ok(n) if n < data.len() => return Err(std::io::ErrorKind::WriteZero.into()),
        Ok(_) => {
            return Ok(true);
        }
        // We are not ready yet
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Ok(false);
        }
        // We can work around this by trying again
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
            return write_stream_data(connection, data)
        }
        // Unexpected errors that are undesired
        Err(e) => return Err(e),
    }
}

fn read_stream_data(
    connection: &mut TcpStream,
    mailbox: &mut VecDeque<Vec<u8>>,
) -> std::io::Result<bool> {
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
