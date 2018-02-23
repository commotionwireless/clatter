//! MDP system services.
//!
//! These are system services that must be run as part of a fully compliant `MDP` network. They
//! listen on low-number `MDP` ports and support services such as mesh routing.

use futures::prelude::*;
use futures::future;
use socket::Socket;
use routing::{Link, LinkState};

/// The routing service.
///
/// This service listens on port 2 by default and supports multi-hop linkstate routing. As this
/// service is also tied to how `MDP` acknowledges packets, it is essential to run as part of any
/// application that requires more than broadcast messaging.
pub struct Routing(Socket);

impl Future for Routing {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let &mut Routing(ref mut s) = self;
        debug!("Running routing service.");
        if let Some((ref msg, _, _)) = try_ready!(s.by_ref().poll()) {
            debug!("Processing linkstate message: {:?}", msg);
            let proto = s.proto().clone();
            let mut proto = proto.lock().unwrap();
            let links = Link::decode_links(msg)?;
            for LinkState(rx, tx, version, iface, ack_seq, ack_mask, drop_rate) in links {
                let rtt = if ack_seq > -1 {
                    let outgoing = proto.outgoing_mut();
                    outgoing.ack(&rx, ack_seq, ack_mask)
                } else {
                    None
                };
                {
                    let routes = proto.routes_mut();
                    routes.seen_link(rx, tx, version, iface, ack_seq, ack_mask, drop_rate);
                    if let Some((min_rtt, max_rtt)) = rtt {
                        if let Some(peer) = routes.get_peer_mut(&rx) {
                            peer.set_rtt(min_rtt, max_rtt);
                        }
                    }
                }
            }
        }
        future::empty().poll()
    }
}

impl From<Socket> for Routing {
    fn from(mut s: Socket) -> Routing {
        s.set_broadcast(true);
        Routing(s)
    }
}
