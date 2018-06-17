//! Start the accompanying mdp-ping on another machine on the same network (make sure both
//! machines' firewalls allow port 4110) and they will send pings back and forth.
//!
//! # Example
//! `cargo run --example mdp-pong

extern crate env_logger;
extern crate bytes;
extern crate futures;
extern crate mdp;
extern crate net2;
extern crate time;
extern crate tokio;

use bytes::BytesMut;
use mdp::protocol::{Protocol, PORT_LINKSTATE};
use mdp::overlay::udp::Interface;
use mdp::addr::{LocalAddr, ADDR_BROADCAST};
use mdp::services::Routing;
use mdp::socket::{BytesCodec, Framed};
use tokio::net::UdpSocket;
use std::net::SocketAddr as IpSocketAddr;
use std::time::Duration;
use futures::{Future, Sink, Stream};

fn main() {
    drop(env_logger::init());

    let b_ip: IpSocketAddr = ("0.0.0.0:4110").parse().unwrap();
    let b_udp = UdpSocket::bind(&b_ip).unwrap();
    b_udp.set_broadcast(true).unwrap();

    let b_addr = LocalAddr::new();

    let b_interface = Interface::new(b_udp).unwrap();

    let mut b_protocol = Protocol::new(&b_addr);

    b_protocol.interface(b_interface);

    let mut b_socket = b_protocol.bind(&b_addr, 555).unwrap();
    b_socket.set_broadcast(true);
    let b_socket = Framed::new(b_socket, BytesCodec::new());
    let b_routing = Routing::from(b_protocol.bind(&b_addr, PORT_LINKSTATE).unwrap());

    let (b_sink, b_stream) = b_socket.split();

    // Start off by sending a ping from a to b, afterwards we just print out
    // what they send us and continually send pings
    // let pings = stream::iter((0..5).map(Ok));
    let mut i = -1;
    let b_stream = b_stream.map(move |(msg, _addr, state)| {
        i += 1;
        println!("[b] recv: {}", String::from_utf8_lossy(&msg));
        println!("[b] send: PONG {}", i);
        (
            BytesMut::from(format!("PONG {}", i).into_bytes()),
            (ADDR_BROADCAST, 555).into(),
            state,
        )
    });
    let b = b_sink.send_all(b_stream);

    // Spawn the sender of pongs and then wait for our pinger to finish.
    tokio::spawn(b_routing);
    tokio::spawn(b.then(|_| Ok(())));
    tokio::run(b_protocol.run(Duration::new(1, 0)));
}
