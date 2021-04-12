use std::iter;

use libp2p::{core::UpgradeInfo, swarm::NegotiatedSubstream, InboundUpgrade, OutboundUpgrade};

use futures::prelude::*;
use void::Void;

#[derive(Default, Debug, Copy, Clone)]
pub struct P2P;

// Three necessary traits for the inbound and outbound substreams
impl UpgradeInfo for P2P {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    // list of supported protocols, used during negotiation process
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/ipfs/abrahm/1.0.0")
    }
}
impl InboundUpgrade<NegotiatedSubstream> for P2P {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        log::debug!("[InboundUpgrade] dummy upgrade_inbound");
        future::ok(stream)
    }
}
impl OutboundUpgrade<NegotiatedSubstream> for P2P {
    type Output = NegotiatedSubstream;
    type Error = Void;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        log::debug!("[OutboundUpgrade] dummy upgrade_outbound");
        future::ok(stream)
    }
}
