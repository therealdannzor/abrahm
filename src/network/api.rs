#![allow(unused)]

use super::client_handle::spawn_peer_listeners;
use super::server_handle::spawn_server_accept_loop;

pub async fn spawn_network_io_listeners(validator_list: Vec<String>, greeting: String) {
    let (message_peer_handle, join_outbound, join_inbound) = spawn_peer_listeners().await;
    let (from_serv_rx, from_serv_tx, mailbox_rx, join_server) =
        spawn_server_accept_loop(validator_list).await;
}
