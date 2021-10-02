#![allow(unused)]

use futures::StreamExt;
use libp2p::{
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn peer_discovery_loop(amount_to_find: usize) -> Result<Vec<String>, Box<dyn Error>> {
    let keys_id = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys_id.public());
    let transport = libp2p::development_transport(keys_id).await?;
    let behavior = Mdns::new(MdnsConfig::default()).await?;
    let mut swarm = Swarm::new(transport, behavior, peer_id);
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut validator_disc_addresses: Vec<String> = Vec::new();

    // search the local network for other peers and bail out when having found 'em all
    while validator_disc_addresses.len() < amount_to_find {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(MdnsEvent::Discovered(peers)) => {
                for (_, addr) in peers {
                    let port = extract_port(addr.clone());
                    validator_disc_addresses.push(port);
                }
            }
            _ => {}
        }
    }

    Ok(validator_disc_addresses)
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

// DiscoveryServer is used to reach out the peers we have discovered, through the
// `peer_discovery_loop`. Each of the peers connected will perform a two-way handshake
// by sending their public key and their port number to one another. The only way we
// verify the legitimacy of each peer is by comparing it to the config file which has
// the "white list" of the peers allowed to be part of our network.
struct DiscoveryServer {
    socket: UdpSocket,
    buf: Vec<u8>,
    recipients: Vec<String>,
    to_send: Option<(usize, SocketAddr)>,
}
