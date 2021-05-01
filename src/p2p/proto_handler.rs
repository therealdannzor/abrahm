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

use super::net_behaviour::MessageCondition;
use super::proto_upgrade::P2P;

type MessageFuture = BoxFuture<'static, Result<NegotiatedSubstream, io::Error>>;

pub struct PeerManager {
    inbound: Option<MessageFuture>,
    outbound: Option<MessageFuture>,
    status: bool,
}

const MSG_SIZE: usize = 6;
impl PeerManager {
    pub fn new(status: bool) -> Self {
        PeerManager {
            inbound: None,
            outbound: None,
            status,
        }
    }
}

pub async fn recv_msg<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = [0u8; MSG_SIZE];

    stream.read_exact(&mut payload).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;

    log::info!("received payload: {:?}", payload);
    Ok(stream)
}

use std::io::prelude::*;

pub async fn send_msg<S>(mut stream: S) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stdin = io::BufReader::new(io::stdin());
    let buf = stdin.fill_buf().unwrap();

    stream.write_all(buf).await?;
    stream.flush().await?;

    let mut recv_bytes_slice = [0u8; MSG_SIZE];
    stream.read_exact(&mut recv_bytes_slice).await?;
    let recv = str::from_utf8(&recv_bytes_slice);

    log::info!("sent payload: {:?}", recv);
    Ok(stream)
}

impl ProtocolsHandler for PeerManager {
    type InEvent = Void;
    type OutEvent = MessageCondition;
    type Error = ReadOneError;
    type InboundProtocol = P2P;
    type OutboundProtocol = P2P;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<P2P, ()> {
        log::debug!("Peer manager: apply listen protocol");
        SubstreamProtocol::new(P2P, ())
    }

    fn inject_fully_negotiated_inbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.inbound.is_some() {
            panic!("inbound exists already");
        }
        log::debug!("Peer manager: negotiated inbound injected, receive stream");
        self.inbound = Some(recv_msg(stream).boxed());
    }

    fn inject_fully_negotiated_outbound(&mut self, stream: NegotiatedSubstream, (): ()) {
        if self.outbound.is_some() {
            panic!("outbound exists already");
        }
        log::debug!("Peer manager: negotiated outbound injected, send stream");

        self.outbound = Some(send_msg(stream).boxed());
    }

    fn inject_event(&mut self, _: Void) {
        log::debug!("Peer manager: inject event");
    }

    fn inject_dial_upgrade_error(&mut self, _info: (), error: ProtocolsHandlerUpgrErr<Void>) {
        log::debug!(
            "Peer manager inject dial upgrade; resolved with:  {:?}",
            error
        );
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ProtocolsHandlerEvent<P2P, (), MessageCondition, Self::Error>> {
        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {
                    log::debug!("Polling: pending inbound");
                }
                Poll::Ready(Ok(stream)) => {
                    log::debug!("Polling: inbound received successfully");
                    self.inbound = Some(recv_msg(stream).boxed());
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(MessageCondition::Success));
                }
                Poll::Ready(Err(e)) => {
                    log::error!("Polling: inbound failed; resolved with error: {:?}", e);
                    panic!();
                }
            }
        }

        match self.outbound.take() {
            Some(mut send_msg_future) => match send_msg_future.poll_unpin(cx) {
                Poll::Pending => {
                    self.outbound = Some(send_msg_future);
                    log::debug!("Polling: outbound pending");
                }
                Poll::Ready(Ok(stream)) => {
                    log::debug!(
                        "Polling: outbound successfully received (stream: {:?})",
                        stream
                    );
                    return Poll::Ready(ProtocolsHandlerEvent::Custom(MessageCondition::Success));
                }
                Poll::Ready(Err(e)) => {
                    log::error!("Polling: outbound resolved with error: {:?}", e);
                    panic!();
                }
            },
            None => {
                if !self.status {
                    self.status = true;
                    let protocol = SubstreamProtocol::new(P2P, ());
                    log::debug!("Polling: outbound substream request");
                    return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                        protocol,
                    });
                }
            }
        }
        Poll::Pending
    }
}
