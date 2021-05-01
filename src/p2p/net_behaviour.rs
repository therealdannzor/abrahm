use std::task::{Context, Poll};
use void::Void;

use libp2p::{
    core::connection::ConnectionId,
    swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};

use super::proto_handler::PeerManager;

#[derive(Debug)]
pub enum MessageCondition {
    Success,
}

#[derive(Debug)]
pub struct PeerEvent {
    pub peer: PeerId,
    pub result: MessageCondition,
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
        log::debug!("Message: inject connected");
    }

    fn inject_disconnected(&mut self, _: &PeerId) {
        log::debug!("Message: inject disconnected");
    }

    fn inject_event(&mut self, peer: PeerId, _: ConnectionId, result: MessageCondition) {
        log::debug!("Message: inject_event");
        self.events.push_front(PeerEvent { peer, result })
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Void, PeerEvent>> {
        if let Some(e) = self.events.pop_back() {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
        } else {
            Poll::Pending
        }
    }
}
