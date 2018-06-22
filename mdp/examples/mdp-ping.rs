//! Start the accompanying mdp-pong on another machine on the same network (make sure both
//! machines' firewalls allow port 4110) and they will send pings back and forth.
//!
//! # Example
//! `cargo run --example mdp-ping

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
use mdp::socket::{Framed, BytesCodec, State};
use mdp::addr::{LocalAddr, ADDR_BROADCAST};
use mdp::services::Routing;
use tokio::net::UdpSocket;
use std::net::SocketAddr as IpSocketAddr;
use std::time::Duration;
use futures::{Future, Sink, Stream};

fn main() {
    drop(env_logger::init());

    let a_ip: IpSocketAddr = ("0.0.0.0:4110").parse().unwrap();
    //    let a_udp = UdpSocket::from_socket(UdpBuilder::new_v4().unwrap().reuse_address(true).unwrap().reuse_port(true).unwrap().bind(a_ip).unwrap(), &handle).unwrap();
    let a_udp = UdpSocket::bind(&a_ip).unwrap();
    a_udp.set_broadcast(true).unwrap();

    let a_addr = LocalAddr::new();

    let a_interface = Interface::new(a_udp).unwrap();

    let mut a_protocol = Protocol::new(&a_addr);

    a_protocol.interface(a_interface);

    let mut a_socket = a_protocol.bind(&a_addr, 555).unwrap();
    a_socket.set_broadcast(true);
    let a_socket = Framed::new(a_socket, BytesCodec::new());
    let a_routing = Routing::from(a_protocol.bind(&a_addr, PORT_LINKSTATE).unwrap());

    let (a_sink, a_stream) = a_socket.split();

    // Start off by sending a ping from a to b, afterwards we just print out
    // what they send us and continually send pings
    // let pings = stream::iter((0..5).map(Ok));
    let a = a_sink
        .send((
            BytesMut::from(&b"PING 0"[..]),
            (ADDR_BROADCAST, 555).into(),
            State::Plain,
        ))
        .and_then(|a_sink| {
            println!("[a] send: PING 0");
            let mut i = 0;
            let a_stream = a_stream.map(move |(msg, _addr, state, _dst_broadcast)| {
                i += 1;
                println!("[a] recv: {}", String::from_utf8_lossy(&msg));
                println!("[a] send: PING {}", i);
                (
                    BytesMut::from(format!("PING {}", i).into_bytes()),
                    (ADDR_BROADCAST, 555).into(),
                    state,
                )
            });
            a_sink.send_all(a_stream)
        });

    // Spawn the sender of pongs and then wait for our pinger to finish.

    //let timer = Timer::default();
    //let a_routing = timer.interval(Duration::from_secs(5)).for_each(|_| a_routing).map_err(|_| ());

    tokio::spawn(a_protocol.run(Duration::new(1, 0)).then(|_| Ok(())));
    tokio::spawn(a_routing);
    tokio::run(a.then(|_| Ok(())));
}
