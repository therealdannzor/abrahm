use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{event::Event, Token};
use std::{
    io,
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::from_utf8,
};

pub fn handle_client_event(
    connection: &mut TcpStream,
    event: &Event,
    payload: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();

    if event.is_writable() && payload.is_some() {
        let data = payload.unwrap();
        if write_stream_data(connection, data).unwrap() {
            result = vec![79, 107]; // 'Ok'
        }
    } else if event.is_readable() {
        result = read_stream_data(connection).unwrap();
    }

    Ok(result)
}

pub fn open_socket() -> TcpListener {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let socket = SocketAddr::new(loopback, 1024);

    let srv = match TcpListener::bind(socket) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    srv
}

// Updates the token to make sure we have unique ones for each stream.
pub fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

// Checks our receive buffer whether there is something to read.
// If this is true, we remove it from the buffer and log it to the user.
// If this is false, we do nothing.
fn check_bytes_read(amount: usize, recv: &mut Vec<u8>) -> Option<&[u8]> {
    if amount != 0 {
        let recv = &recv[..amount];
        if let Ok(buf) = from_utf8(recv) {
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

fn read_stream_data(connection: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut conn_closed = false;
    let mut rcv_dat = vec![0, 255];
    let mut bytes_read = 0;
    let mut result: Vec<u8> = Vec::new();

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
        return Ok(result);
    } else {
        result = octs.unwrap().to_vec();
    }

    if conn_closed {
        info!("connection closed");
    }
    Ok(result)
}
