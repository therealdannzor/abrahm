use std::task::{Context, Poll};

use libp2p::{
    core::connection::ConnectionId,
    swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};

use void::Void;

use super::handler::PeerManager;

#[derive(Debug)]
pub enum MessageStatus {
    Success,
}

#[derive(Debug)]
pub struct PeerEvent {
    pub peer: PeerId,
    pub result: MessageStatus,
}

pub struct StatusConfig {
    pub status: bool,
}

pub struct MessageLog {
    events: std::collections::VecDeque<PeerEvent>,
    config: StatusConfig,
}

#[allow(dead_code)]
impl MessageLog {
    pub fn new(config: StatusConfig) -> Self {
        MessageLog {
            events: std::collections::VecDeque::new(),
            config,
        }
    }
}

impl NetworkBehaviour for MessageLog {
    type ProtocolsHandler = PeerManager;
    type OutEvent = PeerEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        PeerManager::new(self.config.status)
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _: &PeerId) {
        log::debug!("dummy inject_connected");
    }

    fn inject_disconnected(&mut self, _: &PeerId) {
        log::debug!("dummy inject_disconnected");
    }

    fn inject_event(&mut self, peer: PeerId, _: ConnectionId, result: MessageStatus) {
        log::debug!("dummy inject_event");
        self.events.push_front(PeerEvent { peer, result })
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Void, PeerEvent>> {
        log::debug!("Polling events: {:?}", self.events);
        if let Some(e) = self.events.pop_back() {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
        } else {
            Poll::Pending
        }
    }
}
