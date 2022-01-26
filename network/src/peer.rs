#![allow(dead_code)]

use std::io::{self, ErrorKind};
use swiss_knife::helper::new_timestamp;
use tokio::net::TcpStream;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

// Peer is an active connection. It is part of the validator set.
pub struct Peer {
    rw: Option<TcpStream>,

    // Last time a message was received
    last_seen: i64,

    // Fully upgraded
    handshakes: bool,

    // Exit signals
    close_recv: oneshot::Receiver<u8>,
    close_send: oneshot::Sender<u8>,

    // To mock tests
    test_pipe: Option<TestPipe>,
}

const MAX_LENGTH: usize = 550;

struct TestPipe {
    w: Sender<[u8; MAX_LENGTH]>,
    r: Receiver<[u8; MAX_LENGTH]>,
}

impl Peer {
    pub fn new(rw: Option<TcpStream>, test_pipe: Option<TestPipe>) -> Self {
        let last_seen = new_timestamp();
        let handshakes = false;
        let (close_send, close_recv): (oneshot::Sender<u8>, oneshot::Receiver<u8>) =
            oneshot::channel();
        Self {
            rw,
            last_seen,
            handshakes,
            close_recv,
            close_send,
            test_pipe,
        }
    }

    pub async fn send(&self, msg: [u8; MAX_LENGTH]) -> Result<(), io::Error> {
        let l = msg.len();
        if self.rw.is_some() {
            loop {
                let send = self.rw.as_ref().unwrap();
                let _ = send.writable().await;

                match send.try_write(&msg) {
                    Ok(n) => {
                        if n != l {
                            return Err(io::Error::new(
                                ErrorKind::BrokenPipe,
                                "sent incomplete message",
                            ));
                        }
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        } else if self.test_pipe.is_some() {
            let s = &self.test_pipe.as_ref().unwrap().w;
            s.send(msg);
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "neither tcp stream nor test pipe exists",
            ));
        }

        Ok(())
    }

    pub async fn recv(&self) -> Result<[u8; MAX_LENGTH], io::Error> {
        if self.rw.is_some() {
            loop {
                let recv = self.rw.as_ref().unwrap();
                let _ = recv.readable().await;
                let mut buf = [0; MAX_LENGTH];

                match recv.try_read(&mut buf) {
                    Ok(0) => {
                        continue;
                    }
                    Ok(_n) => {
                        return Ok(buf);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        } else if self.test_pipe.is_some() {
            let r = &self.test_pipe.as_ref().unwrap().r;
            if let Some(msg) = r.recv().await {
                return Ok(msg);
            } else {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "received empty message",
                ));
            }
        } else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "neither tcp stream nor test pipe exists",
            ));
        }
    }

    pub fn update_last_seen(&mut self) -> i64 {
        let ts = new_timestamp();
        self.last_seen = ts;
        ts
    }
}
