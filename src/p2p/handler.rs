use std::{
    io, str,
    task::{Context, Poll},
};

use libp2p::{
    core::upgrade::ReadOneError,
    swarm::{
        KeepAlive, NegotiatedSubstream, ProtocolsHandler, ProtocolsHandlerEvent,
        ProtocolsHandlerUpgrErr, SubstreamProtocol,
    },
};

use void::Void;

use futures::future::BoxFuture;
use futures::prelude::*;

use super::message_log::MessageStatus;
use super::protocol::P2P;

type MessageFuture = BoxFuture<'static, Result<NegotiatedSubstream, io::Error>>;

pub struct PeerManager {
    inbound: Option<MessageFuture>,
    outbound: Option<MessageFuture>,
    status: bool,
    already_echo: bool,
}

impl PeerManager {
    pub fn new(status: bool) -> Self {
        PeerManager {
            inbound: None,
            outbound: None,
            status,
            already_echo: false,
        }
    }
}

const MSG_SIZE: usize = 6;
pub async fn recv_msg<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = [0u8; MSG_SIZE];
    log::debug!("recv_msg, wait for message");

    stream.read_exact(&mut payload).await?;
    log::debug!("recv_msg, payload size in stream satisfied: {:?}", payload);

    stream.write_all(&payload).await?;
    stream.flush().await?;
    log::debug!("recv_msg successfull for payload: {:?}", payload);

    Ok(stream)
}

pub async fn send_msg<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // payload is the 2nd CLI arg
    let arg1 = std::env::args().nth(2);

    let payload = arg1.unwrap();

    stream.write_all(payload.as_bytes()).await?;
    stream.flush().await?;

    let mut recv_bytes_slice = [0u8; MSG_SIZE];
    stream.read_exact(&mut recv_bytes_slice).await?;
    let recv = str::from_utf8(&recv_bytes_slice);
    log::info!("send_msg, clear for transmission: {:?}", recv);
    if recv == Ok(&payload) {
        Ok(stream)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload length mismatch: confirm the payload byte size",
        ))
    }
}

impl ProtocolsHandler for PeerManager {
    type InEvent = Void;
    type OutEvent = MessageStatus;
    type Error = ReadOneError;
    type InboundProtocol = P2P;
    type OutboundProtocol = P2P;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<P2P, ()> {
        SubstreamProtocol::new(P2P, ())
    }

    fn inject_fully_negotiated_inbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.inbound.is_some() {
            panic!("inbound exists already");
        }
        log::debug!("dummy inject_fully_negotiated_inbound");
        self.inbound = Some(recv_msg(stream).boxed());
    }

    fn inject_fully_negotiated_outbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.outbound.is_some() {
            panic!("outbound exists already");
        }
        log::debug!("dummy inject_fully_negotiated_inbound");

        self.outbound = Some(send_msg(stream).boxed());
    }

    fn inject_event(&mut self, _: Void) {}

    fn inject_dial_upgrade_error(&mut self, _info: (), error: ProtocolsHandlerUpgrErr<Void>) {
        log::debug!("dummy inject_dial_upgrade_error: {:?}", error);
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ProtocolsHandlerEvent<P2P, (), MessageStatus, Self::Error>> {
        log::debug!("Polling initialized");

        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {
                    log::debug!("Polling pending");
                }
                Poll::Ready(Err(e)) => {
                    log::error!("Polling failed; resolved with error: {:?}", e);
                    self.inbound = None;
                    panic!();
                }
                Poll::Ready(Ok(stream)) => {
                    log::debug!("Polled and received successfully");
                    self.inbound = Some(recv_msg(stream).boxed());
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(MessageStatus::Success));
                }
            }
        }

        match self.outbound.take() {
            Some(mut send_msg_future) => match send_msg_future.poll_unpin(cx) {
                Poll::Pending => {
                    self.outbound = Some(send_msg_future);
                    log::debug!("Polling outbound pending");
                }
                Poll::Ready(Ok(_stream)) => {
                    log::debug!("Polling outbound successfully received");
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(MessageStatus::Success));
                }
                Poll::Ready(Err(e)) => {
                    log::error!("Polling, outbound resolved with error: {:?}", e);
                    panic!();
                }
            },
            None => {
                log::debug!(
                    "Polling, outbound is none, waiting for negotation with outbound stream"
                );
                if self.status && !self.already_echo {
                    self.already_echo = true;
                    let protocol = SubstreamProtocol::new(P2P, ());
                    return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                        protocol,
                    });
                }
            }
        }
        Poll::Pending
    }
}
