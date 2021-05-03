// Adapted from https://blog.logrocket.com/how-to-build-a-websocket-server-with-rust/
#![allow(unused)]

use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;
use warp::Filter;

use super::ws_handler as func;
use super::ws_peer::Peers;

fn with_peers(peers: Peers) -> impl Filter<Extract = (Peers,), Error = Infallible> + Clone {
    warp::any().map(move || peers.clone())
}

pub async fn serve_routes() {
    let peers: Peers = Arc::new(RwLock::new(HashMap::new()));

    // heartbeat endpoint
    let health_route = warp::path!("health").and_then(func::health);

    // register peer endpoint
    let register = warp::path!("register");
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
    let publish = warp::path!("publish")
        .and(warp::body::json())
        .and(with_peers(peers.clone()))
        .and_then(func::publish);

    // websocket
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(warp::path::param())
        .and(with_peers(peers.clone()))
        .and_then(func::conn_socket);

    // warp filter of all the routes
    let routes = health_route
        .or(register_routes)
        .or(ws_route)
        .or(publish)
        .with(warp::cors().allow_any_origin());

    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}
