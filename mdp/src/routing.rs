use petgraph::graph::{DiGraph, EdgeIndex, EdgeReference, NodeIndex};
use petgraph::Direction;
use petgraph::visit::{EdgeRef, IntoNodeReferences, VisitMap, Visitable};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashSet;
use std::cell::Cell;
use error::{Error, Result};
use addr::{address_parse, Addr, ADDR_BROADCAST, ADDR_EMPTY};
use util::BitMask;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};
use std::u32;
use std::u64;
use std::vec::IntoIter;
use bytes::{BigEndian, BufMut};
use nom::{ErrorKind, IResult, be_i8, be_u32, be_u8};

const ACK_WINDOW_FRAME: u32 = 32;
const ACK_WINDOW_PACKET: u32 = 64;
const ACK_WINDOW_MAX: u32 = 127;
pub(crate) const LINKSTATE_DELAY_MS: u64 = 5000;
const RESEND_GRACE_MS: u64 = 40;

bitflags! {
    pub struct LinkFlags: u8 {
        const LINK_INTERFACE = 0b0000_0001;
        const LINK_NO_PATH = 0b0000_0010;
        const LINK_BROADCAST = 0b0000_0100;
        const LINK_UNICAST = 0b0000_1000;
        const LINK_ACK = 0b0001_0000;
        const LINK_DROP_RATE = 0b0010_0000;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Peer {
    addr: Addr,
    lock: bool,
    ack_seq: i8,
    ack_mask: u64,
    last_ack_sent: i8,
    last_seen: Instant,
    ack_promptly: bool,
    bcast_forward: Instant,
    send_full: bool,
    max_rtt: Duration,
    min_rtt: Duration,
}

impl Peer {
    fn new(addr: Addr) -> Peer {
        Peer {
            addr: addr,
            lock: true,
            ack_seq: -1,
            ack_mask: 0,
            last_ack_sent: -1,
            last_seen: Instant::now(),
            ack_promptly: false,
            bcast_forward: Instant::now(),
            send_full: true,
            max_rtt: Duration::new(0, 0),
            min_rtt: Duration::new(0, 0),
        }
    }

    fn seen(&mut self) {
        self.last_seen = Instant::now()
    }

    pub(crate) fn set_rtt(&mut self, min_rtt: Duration, max_rtt: Duration) {
        self.min_rtt = min_rtt;
        self.max_rtt = max_rtt;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Link {
    version: i8,
    iface: i8,
    ack_seq: i8,
    ack_mask: u32,
    drop_rate: i8,
    last_sent_seq: i8,
    send: Cell<bool>,
    send_at: Cell<Instant>,
    last_seen: Instant,
}

impl Link {
    pub(crate) fn new(iface: i8, seq: i8) -> Link {
        Link {
            version: -1,
            iface: iface,
            ack_seq: seq,
            ack_mask: 0,
            drop_rate: -1,
            last_sent_seq: -1,
            send: Cell::new(false),
            send_at: Cell::new(Instant::now()),
            last_seen: Instant::now(),
        }
    }

    pub(crate) fn schedule(&self, time: Duration) {
        self.send.set(true);
        self.send_at.set(Instant::now() + time);
    }

    fn seen(&mut self) {
        self.last_seen = Instant::now()
    }

    pub(crate) fn is_sendable(&self) -> bool {
        self.send.get() && self.send_at.get() >= Instant::now()
    }

    pub(crate) fn encode<B: BufMut>(&self, rx: &Addr, tx: &Addr, buf: &mut B) -> Result<usize> {
        let mut flags = LinkFlags { bits: 0 };
        if tx == &ADDR_EMPTY {
            flags.insert(LinkFlags::LINK_NO_PATH)
        };
        if self.iface >= 0 {
            flags.insert(LinkFlags::LINK_INTERFACE)
        };
        if self.ack_seq >= 0 {
            flags.insert(LinkFlags::LINK_ACK)
        };
        if self.drop_rate >= 0 {
            flags.insert(LinkFlags::LINK_DROP_RATE)
        };
        let before: usize = buf.remaining_mut();
        buf.put_u8(0);
        buf.put_u8(flags.bits);
        buf.put_slice(rx.as_ref());
        buf.put_i8(self.version);
        if tx != &ADDR_EMPTY {
            buf.put_slice(tx.as_ref());
        };
        if self.iface >= 0 {
            buf.put_i8(self.iface);
        };
        if self.ack_seq >= 0 {
            buf.put_i8(self.ack_seq);
            buf.put_u32::<BigEndian>(self.ack_mask);
        };
        if self.drop_rate >= 0 {
            buf.put_i8(self.drop_rate);
        };
        Ok(before - buf.remaining_mut())
    }

    fn decode_link_payload(buf: &[u8]) -> IResult<&[u8], LinkState> {
        let (r, _) = try_parse!(buf, tag!([0]));
        let (r, bits) = try_parse!(r, be_u8);
        let flags = match LinkFlags::from_bits(bits) {
            Some(flags) => flags,
            None => return IResult::Error(ErrorKind::Custom(42)),
        };
        let (r, rx): (&[u8], Addr) = try_parse!(r, address_parse);
        let (r, version) = try_parse!(r, be_i8);
        let (r, tx): (&[u8], Addr) = if !flags.contains(LinkFlags::LINK_NO_PATH) {
            try_parse!(r, address_parse)
        } else {
            (r, ADDR_EMPTY)
        };
        let (r, iface): (&[u8], i8) = if flags.contains(LinkFlags::LINK_INTERFACE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        let (r, (ack_seq, ack_mask)) = if flags.contains(LinkFlags::LINK_ACK) {
            try_parse!(r, tuple!(be_i8, be_u32))
        } else {
            (r, (-1, 0))
        };
        let (r, drop_rate) = if flags.contains(LinkFlags::LINK_DROP_RATE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        IResult::Done(
            r,
            LinkState(rx, tx, version, iface, ack_seq, ack_mask, drop_rate),
        )
    }

    pub(crate) fn decode_links(buf: &[u8]) -> Result<IntoIter<LinkState>> {
        match many1!(buf, Link::decode_link_payload) {
            IResult::Done(_, links) => {
                Ok(links.into_iter())
            }
            IResult::Incomplete(needed) => Err(Error::ParseIncomplete(needed)),
            IResult::Error(err) => Err(Error::ParseError(err)),
        }
    }
}

pub(crate) struct LinkState(
    pub(crate) Addr,
    pub(crate) Addr,
    pub(crate) i8,
    pub(crate) i8,
    pub(crate) i8,
    pub(crate) u32,
    pub(crate) i8,
);

#[derive(Debug, Clone, PartialEq)]
struct Hop {
    cost: u32,
    edge: EdgeIndex,
}

impl Hop {
    fn new(cost: u32, edge: EdgeIndex) -> Hop {
        Hop {
            cost: cost,
            edge: edge,
        }
    }
}

impl Eq for Hop {}

impl PartialOrd for Hop {
    fn partial_cmp(&self, other: &Hop) -> Option<Ordering> {
        self.cost.partial_cmp(&other.cost)
    }
}

impl Ord for Hop {
    fn cmp(&self, other: &Hop) -> Ordering {
        self.cost.cmp(&other.cost)
    }
}

#[derive(Debug)]
pub struct Table {
    default_addr: Addr,
    base_timeout: Duration,
    peers: DiGraph<Peer, Link>,
    next_hop: HashMap<Addr, Hop>,
    local_addrs: HashSet<Addr>,
    local_last_sent: Instant,
    dirty: bool,
}

impl Table {
    pub fn new(default_addr: &Addr, base_timeout: Duration) -> Table {
        let mut peers = DiGraph::new();
        peers.add_node(Peer::new(*default_addr));
        Table {
            default_addr: *default_addr,
            base_timeout: base_timeout,
            peers: peers,
            next_hop: HashMap::new(),
            local_addrs: HashSet::new(),
            local_last_sent: Instant::now(),
            dirty: false,
        }
    }

    fn link_cost(&self, edge: EdgeReference<Link>) -> Option<u32> {
        let link = edge.weight();
        if link.last_seen + self.base_timeout > Instant::now() {
            if link.drop_rate >= 0 {
                Some(1 / (1 - link.drop_rate as u32 / i8::max_value() as u32))
            } else {
                Some(1)
            }
        } else {
            None
        }
    }

    pub fn find_next_hops(&mut self) {
        debug!("Rebuilding routing table.");
        let mut visited = self.peers.visit_map();
        let mut visit_next = BinaryHeap::new();
        self.next_hop.clear();
        //Collect neighbors
        let local_id = self.get_node(&self.default_addr).unwrap();
        visited.visit(local_id);
        for edge in self.peers.edges_directed(local_id, Direction::Outgoing) {
            if let Some(cost) = self.link_cost(edge) {
                let neighbor = edge.target();
                //visited.visit(neighbor);
                if let Some(peer) = self.peers.node_weight(neighbor) {
                    match self.next_hop.entry(peer.addr) {
                        Occupied(e) => {
                            if cost < e.get().cost {
                                *e.into_mut() = Hop::new(cost, edge.id());
                            };
                        }
                        Vacant(e) => {
                            e.insert(Hop::new(cost, edge.id()));
                        }
                    };
                };
            };
        }
        //Run Dijkstra from each neighbor and record neighbor w/ shortest path
        for edge in self.peers.edges_directed(local_id, Direction::Outgoing) {
            if let Some(cost) = self.link_cost(edge) {
                visit_next.push(Hop::new(cost, edge.id()));
            }
            while let Some(Hop { cost, edge }) = visit_next.pop() {
                if let Some((_, node_id)) = self.peers.edge_endpoints(edge) {
                    if visited.is_visited(&node_id) {
                        continue;
                    };
                    for edge in self.peers.edges(node_id) {
                        let next = edge.target();
                        if visited.is_visited(&next) {
                            continue;
                        };
                        if let Some(next_peer) = self.peers.node_weight(next) {
                            if let Some(c) = self.link_cost(edge) {
                                let mut next_cost = cost + c;
                                match self.next_hop.entry(next_peer.addr) {
                                    Occupied(e) => if next_cost < e.get().cost {
                                        *e.into_mut() = Hop::new(next_cost, edge.id());
                                    } else {
                                        next_cost = e.get().cost;
                                    },
                                    Vacant(e) => {
                                        e.insert(Hop::new(next_cost, edge.id()));
                                    }
                                }
                                let next_hop = Hop::new(next_cost, edge.id());
                                visit_next.push(next_hop);
                                visited.visit(next);
                            };
                        };
                    }
                };
            }
        }
    }

    fn get_node(&self, peer: &Addr) -> Option<NodeIndex> {
        let peer = peer.into();
        self.peers
            .node_references()
            .find(|&(_, weight)| weight.addr == peer)
            .map(|(index, _)| index)
    }

    fn get_peer(&self, peer: &Addr) -> Option<&Peer> {
        let peer = peer.into();
        self.peers
            .node_references()
            .find(|&(_, weight)| weight.addr == peer)
            .map(|(_, weight)| weight)
    }

    pub(crate) fn get_peer_mut<A: Into<Addr>>(&mut self, peer: A) -> Option<&mut Peer> {
        let peer = peer.into();
        self.peers.node_weights_mut().find(|p| p.addr == peer)
    }

    fn get_edge(&self, rx: NodeIndex, tx: NodeIndex, iface: i8) -> Option<EdgeIndex> {
        self.peers
            .edges_directed(rx, Direction::Incoming)
            .find(|e| {
                let t = e.source();
                t == tx && self.peers[e.id()].iface == iface
            })
            .map(|e| e.id())
    }

    fn get_link_mut(&mut self, rx: NodeIndex, tx: NodeIndex, iface: i8) -> Option<&mut Link> {
        self.get_edge(rx, tx, iface)
            .map(move |e| &mut self.peers[e])
    }

    pub fn insert_local<A: Into<Addr>>(&mut self, addr: A) -> bool {
        self.local_addrs.insert(addr.into())
    }

    //pub fn remove_local<A: Into<Addr>>(&mut self, addr: A) -> bool {
    //    self.local_addrs.remove(&addr.into())
    //}

    pub fn is_local<A: Into<Addr>>(&self, addr: A) -> bool {
        self.local_addrs.contains(&addr.into())
    }

    pub fn local_addrs(&self) -> &HashSet<Addr> {
        &self.local_addrs
    }

    pub fn local_last_sent(&self) -> &Instant {
        &self.local_last_sent
    }

    pub fn set_local_last_sent(&mut self, time: Instant) {
        self.local_last_sent = time
    }

    pub fn resend_delay(&self, peer: &Addr) -> Duration {
        let zero = Duration::new(0, 0);
        if let Some(peer) = self.get_peer(peer) {
            if peer.min_rtt != zero {
                return peer.min_rtt * 2 + Duration::from_millis(RESEND_GRACE_MS);
            }
        }
        zero
    }

    pub fn is_duplicate_frame<A: Into<Addr> + Copy>(&mut self, src: A, iface: i8, seq: i8) -> bool {
        if seq < 0 {
            return false;
        }
        let src = src.into();
        let local_id = self.get_node(&self.default_addr).unwrap();
        let index = self.get_node(&src)
            .unwrap_or_else(|| self.peers.add_node(Peer::new(src)));
        if let Some(link) = self.get_link_mut(local_id, index, iface) {
            link.seen();
            if link.ack_seq < 0 {
                link.ack_seq = seq;
                return false;
            }

            if link.ack_seq == seq {
                return true;
            }

            let delta = (link.ack_seq - seq).abs() as u32;
            if delta <= ACK_WINDOW_FRAME {
                if link.ack_seq > seq {
                    if link.ack_mask.nth_bit_is_set(delta) {
                        return true;
                    } else {
                        link.ack_mask |= 1u32.wrapping_shl(delta - 1);
                    }
                } else {
                    link.ack_mask = link.ack_mask.wrapping_shl(delta);
                    link.ack_mask |= 1u32.wrapping_shl(delta - 1);
                    link.ack_seq = seq;
                }
            } else {
                link.ack_mask = 0;
                link.ack_seq = seq;
            }
            return false;
        };
        self.peers.add_edge(index, local_id, Link::new(iface, seq));
        false
    }

    //pub fn is_peer<A: Into<Addr>>(&self, peer: A) -> bool {
    //    self.get_peer(&peer.into()).is_some()
    //}

    pub fn is_duplicate_packet<A: Into<Addr>>(&mut self, src: A, seq: i8) -> bool {
        if let Some(peer) = self.get_peer_mut(src) {
            peer.seen();
            if peer.ack_seq < 0 {
                peer.ack_seq = seq;
                return false;
            }

            if peer.ack_seq == seq {
                return true;
            }

            let delta = (peer.ack_seq.wrapping_sub(seq)).abs() as u32;
            if delta < ACK_WINDOW_PACKET {
                if peer.ack_seq > seq {
                    if peer.ack_mask.nth_bit_is_set(delta) {
                        return true;
                    } else {
                        peer.ack_mask |= 1u64.wrapping_shl(delta - 1);
                    }
                } else {
                    peer.ack_mask = peer.ack_mask.wrapping_shl(delta);
                    peer.ack_mask |= 1u64.wrapping_shl(delta - 1);
                    peer.ack_seq = seq;
                }
            } else {
                peer.ack_mask = 0;
                peer.ack_seq = seq;
            }
        }
        false
    }

    pub fn seen_link<A: Into<Addr> + Copy>(
        &mut self,
        rx: A,
        tx: A,
        version: i8,
        iface: i8,
        ack_seq: i8,
        ack_mask: u32,
        drop_rate: i8,
    ) {
        let rx = rx.into();
        let tx = tx.into();
        let rx_index = self.get_node(&rx)
            .unwrap_or_else(|| self.peers.add_node(Peer::new(rx)));
        let tx_index = self.get_node(&tx)
            .unwrap_or_else(|| self.peers.add_node(Peer::new(tx)));
        if let Some(link) = self.get_link_mut(rx_index, tx_index, iface) {
            if version > link.version {
                link.version = version;
                if drop_rate >= 0 {
                    link.drop_rate = drop_rate;
                }
                if link.last_sent_seq >= 0 {
                    let delta = (link.last_sent_seq - ack_seq - 1).abs() as u32;
                    if delta < ACK_WINDOW_FRAME && (delta == 0 || ack_mask.nth_bit_is_set(delta)) {
                        link.last_sent_seq = -1;
                    } else if delta <= ACK_WINDOW_MAX {
                        link.schedule(Duration::from_millis(500));
                    }
                }
            }
            link.seen();
            return;
        }
        {
            let mut link = Link::new(iface, ack_seq);
            if drop_rate >= 0 {
                link.drop_rate = drop_rate;
            } else if ack_seq >= 0 {
                link.drop_rate = ack_mask.count_ones() as i8;
            }
            if version > link.version {
                link.version = version;
                link.drop_rate = drop_rate;
            }
            link.schedule(Duration::from_millis(LINKSTATE_DELAY_MS));
            self.peers.add_edge(tx_index, rx_index, link);
        };
        self.dirty = true;
    }

    //pub fn is_reachable<A: Into<Addr>>(&self, p: A) -> bool {
    //    self.next_hop.get(&p.into()).is_some()
    //}

    pub fn next_hop<A: Into<Addr>>(&self, peer: A) -> Option<(Addr, i8)> {
        debug!("Next hops: {:?}", self.next_hop);
        let peer = &peer.into();
        if peer == &ADDR_BROADCAST {
            return Some((ADDR_EMPTY, -1));
        }
        if let Some(&Hop { edge, .. }) = self.next_hop.get(&peer.into()) {
            if let Some((_, target)) = self.peers.edge_endpoints(edge) {
                Some((self.peers[target].addr, self.peers[edge].iface))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn seen_tx<A: Into<Addr>>(&mut self, peer: A, iface: i8) {
        let peer = peer.into();
        let index = self.get_node(&peer)
            .unwrap_or_else(|| self.peers.add_node(Peer::new(peer)));
        self.peers[index].bcast_forward = Instant::now();
        let local_id = self.get_node(&self.default_addr).unwrap();
        if !self.peers.contains_edge(index, local_id) {
            debug!(
                "Adding new incoming link on interface {} from peer {:?}.",
                iface, peer
            );
            self.peers.add_edge(index, local_id, Link::new(iface, -1));
        }
    }

    //pub fn seen_src<A: Into<Addr>>(&mut self, peer: A) {
    //    let peer = peer.into();
    //    self.get_node(&peer)
    //        .unwrap_or_else(|| self.peers.add_node(Peer::new(peer)));
    //}

    pub fn forward_broadcasts<A: Into<Addr>>(&mut self, peer: A) -> bool {
        let interval = match self.get_peer_mut(peer) {
            Some(p) => Instant::now() - p.bcast_forward,
            None => {
                return false;
            }
        };
        interval <= self.base_timeout
    }

    pub fn get_neighbors(&self, iface: i8) -> Option<Vec<Addr>> {
        let local_id = self.get_node(&self.default_addr).unwrap();
        let mut neighbors = Vec::new();
        for edge in self.peers.edges_directed(local_id, Direction::Outgoing) {
            let link = edge.weight();
            let neighbor = edge.target();
            if link.iface == iface || iface < 0 {
                if let Some(peer) = self.peers.node_weight(neighbor) {
                    neighbors.push(peer.addr);
                }
            }
        }
        if !neighbors.is_empty() {
            neighbors.sort();
            neighbors.dedup();
            Some(neighbors)
        } else {
            None
        }
    }

    pub(crate) fn walk_links<F: FnMut((&Addr, &Addr, &Link))>(&mut self, visit: F) {
        debug!("Walking routing table.");
        self.peers
            .edge_references()
            .map(|e| {
                (
                    &self.peers[e.source()].addr,
                    &self.peers[e.target()].addr,
                    e.weight(),
                )
            })
            .for_each(visit);
    }
}
