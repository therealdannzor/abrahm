mod blockchain;
mod cli;
mod consensus;
mod ledger;
mod network;
mod swiss_knife;
mod types;

/// use crate::blockchain::{broadcast_root_hash, start_listeners, Blockchain};
/// use crate::network::api::Networking;
/// use tokio::sync::mpsc;
/// use tokio::time::{sleep, Duration};
/// #[tokio::main]
/// async fn main() {
///     pretty_env_logger::init();
///
///     let notify = std::sync::Arc::new(tokio::sync::Notify::new());
///
///     let (snd, _rcv) = mpsc::channel(8);
///     let mut bc = Blockchain::new(12, None, None, snd);
///     let mut net = Networking::new();
///     let peers = bc.peers_str();
///     let pk = bc.public_type();
///     let sk = bc.secret_type();
///
///     let secret = sk.clone();
///     let public = pk.clone();
///     let validators = peers.clone();
///     let notify2 = notify.clone();
///     let root_hash = bc.root_hash();
///
///     net = start_listeners(net, public, secret, validators, notify2, root_hash.clone()).await;
///     notify.notified().await;
///
///     broadcast_root_hash(root_hash, net, sk).await;
///     notify.notified().await;
/// }
fn main() {}
