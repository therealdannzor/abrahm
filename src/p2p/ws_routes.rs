// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;
use warp::Filter;

use super::ws_handler as func;
use super::ws_peer::Peers;

fn with_peers(peers: Peers) -> impl Filter<Extract = (Peers,), Error = Infallible> + Clone {
    warp::any().map(move || peers.clone())
}

#[allow(dead_code)]
pub async fn serve_routes() -> oneshot::Sender<bool> {
    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));

    // heartbeat endpoint
    let health_route = warp::path!("health").and_then(func::health);

    // register peer endpoint
    let register = warp::path("register");
    let register_routes = register
        .and(warp::post())
        .and(warp::body::json())
        .and(with_peers(peers.clone()))
        .and_then(func::register)
        .or(register
            .and(warp::delete())
            .and(warp::path::param())
            .and(with_peers(peers.clone()))
            .and_then(func::unregister));

    // publish event endpoint
    let publish = warp::path("publish")
        .and(warp::body::json())
        .and(with_peers(peers.clone()))
        .and_then(func::publish);

    // websocket
    let ws_route = warp::path("store")
        .and(warp::ws())
        .and(with_peers(peers.clone()))
        .and(warp::path::tail())
        .and_then(func::messagestore);

    // warp filter of all the routes
    let routes = health_route
        .or(register_routes)
        .or(ws_route)
        .or(publish)
        .with(warp::cors().allow_any_origin());

    // setup server so that it can exist in a gracefully way through a tx channel
    let (tx, rx): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
    let (_, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 8000), async {
            rx.await.ok();
        });

    tokio::task::spawn(server);
    tx
}
