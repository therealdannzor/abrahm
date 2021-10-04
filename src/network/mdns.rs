#![allow(unused)]

use crate::hashed;
use crate::swiss_knife::helper::{generate_hash_from_input, sign_message_digest};
use async_std::{io, task};
use futures::StreamExt;
use futures::{future, prelude::*};
use libp2p::{
    floodsub::{self, Floodsub, FloodsubEvent},
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{NetworkBehaviourEventProcess, Swarm, SwarmEvent},
    NetworkBehaviour, PeerId,
};
use std::error::Error;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;

pub async fn peer_discovery_loop(amount_to_find: usize) -> Result<(), Box<dyn Error>> {
    let keys_id = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys_id.public());
    let transport = libp2p::development_transport(keys_id).await?;
    let floodsub_topic = floodsub::Topic::new("discovery");

    #[derive(NetworkBehaviour)]
    #[behaviour(out_event = "OutEvent")]
    struct MyBehaviour {
        floodsub: Floodsub,
        mdns: Mdns,

        #[behaviour(ignore)]
        #[allow(dead_code)]
        ignored_member: bool,
    }

    #[derive(Debug)]
    enum OutEvent {
        Floodsub(FloodsubEvent),
        Mdns(MdnsEvent),
    }

    impl From<MdnsEvent> for OutEvent {
        fn from(v: MdnsEvent) -> Self {
            Self::Mdns(v)
        }
    }

    impl From<FloodsubEvent> for OutEvent {
        fn from(v: FloodsubEvent) -> Self {
            Self::Floodsub(v)
        }
    }

    impl NetworkBehaviourEventProcess<FloodsubEvent> for MyBehaviour {
        fn inject_event(&mut self, message: FloodsubEvent) {
            if let FloodsubEvent::Message(msg) = message {
                log::info!(
                    "Received: {:?} from {:?}",
                    String::from_utf8_lossy(&msg.data),
                    msg.source
                );
            }
        }
    }

    impl NetworkBehaviourEventProcess<MdnsEvent> for MyBehaviour {
        fn inject_event(&mut self, event: MdnsEvent) {
            match event {
                MdnsEvent::Discovered(list) => {
                    for (peer, _) in list {
                        self.floodsub.add_node_to_partial_view(peer);
                    }
                }
                MdnsEvent::Expired(list) => {
                    for (peer, _) in list {
                        if !self.mdns.has_node(&peer) {
                            self.floodsub.remove_node_from_partial_view(&peer);
                        }
                    }
                }
            }
        }
    }

    let mut swarm = {
        let mdns = task::block_on(Mdns::new(MdnsConfig::default()))?;
        let mut behaviour = MyBehaviour {
            floodsub: Floodsub::new(peer_id),
            mdns,
            ignored_member: false,
        };

        behaviour.floodsub.subscribe(floodsub_topic.clone());
        Swarm::new(transport, behaviour, peer_id)
    };

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut validator_disc_addresses: Vec<String> = Vec::new();

    // search the local network for other peers and bail out when having found 'em all
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(SwarmEvent::NewListenAddr { address, .. })) => {
                    log::info!("Listening on {:?}", address);
                }
                Poll::Ready(Some(SwarmEvent::Behaviour(OutEvent::Floodsub(
                    FloodsubEvent::Message(msg),
                )))) => {
                    log::info!(
                        "Received: {:?} from {:?}",
                        String::from_utf8_lossy(&msg.data),
                        msg.source
                    );
                }
                Poll::Ready(Some(SwarmEvent::Behaviour(OutEvent::Mdns(
                    MdnsEvent::Discovered(list),
                )))) => {
                    for (peer, _) in list {
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .add_node_to_partial_view(peer);
                    }
                }
                Poll::Ready(Some(_)) => {}
                Poll::Ready(None) => {}
                Poll::Pending => break,
            }
        }
        Poll::Pending
    }))
}

fn extract_port(multi_address: libp2p::Multiaddr) -> String {
    let addr_as_u8_vec = &multi_address.to_vec();
    let conv = match std::str::from_utf8(addr_as_u8_vec) {
        Ok(s) => s.to_string(),
        Err(e) => {
            panic!("this should not happen: {:?}", e);
        }
    };

    let sep: Vec<&str> = conv.split("/").collect();
    let last_ind = sep.len() - 1;
    let port = sep[last_ind];
    port.to_string()
}

// create_discv_handshake creates a discovery handshake message containing the:
// * client's public key,
// * port to communicate with the server; and
// * a signature of the hash of these two items.
//
// More formally, a message looks like so
// { PUBLIC_KEY | PORT | H(PUBLIC_KEY | PORT)_C }
// where '|' denotes append and H(x)_C a client C signing a hash of a message {x}
fn create_discv_handshake(
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    port_string: String,
) -> Vec<u8> {
    // store the message here
    let mut message: Vec<u8> = Vec::new();

    let k = public_key.as_ref().to_vec();
    let mut k = match std::str::from_utf8(&k) {
        Ok(key) => key,
        Err(e) => panic!("this should not happen (upstream error key): {:?}", e),
    };
    k.to_string().push_str(&port_string);
    message.extend(k.as_bytes().to_vec()); // adds public key + port to the buffer
    let key_and_port_hashed = hashed!(k);
    let signed = sign_message_digest(secret_key, key_and_port_hashed.as_ref());
    message.extend(signed); // add the signed hash to the buffer
    message
}
