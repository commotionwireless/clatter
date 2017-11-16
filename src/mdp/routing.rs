use petgraph::graph::{DiGraph, EdgeIndex, EdgeReference, NodeIndex};
use petgraph::Direction;
use petgraph::visit::{EdgeRef, Visitable, VisitMap};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashSet;
use mdp::error::{Error, Result};
use mdp::addr::{address_parse, Addr, ADDR_EMPTY};
use mdp::packet::Packet;
use mdp::util::BitMask;
use nom::{IResult, ErrorKind, be_i8, be_u8, be_u32};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};
use bytes::{BufMut, BigEndian};

const ADDR_LOCAL: Addr = ADDR_EMPTY;
const ACK_WINDOW_FRAME: i8 = 32;
const ACK_WINDOW_PACKET: i8 = 64;
const ACK_WINDOW_MAX: i8 = 127;

bitflags! {
    flags LinkFlags: u8 {
        const LINK_INTERFACE = 0b00000001,
        const LINK_NO_PATH = 0b00000010,
        const LINK_BROADCAST = 0b00000100,
        const LINK_UNICAST = 0b00001000,
        const LINK_ACK = 0b00010000,
        const LINK_DROP_RATE = 0b00100000
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Peer {
    addr: Addr,
    lock: bool,
    ack_seq: i8,
    ack_mask: u64,
    last_ack_sent: i8,
    last_seen: Instant,
    ack_promptly: bool,
    bcast_forward: bool,
    send_full: bool
}

impl Peer {
    fn new(addr: Addr) -> Peer {
        Peer {
            addr: addr,
            lock: true,
            ack_seq: 0,
            ack_mask: 0,
            last_ack_sent: -1,
            last_seen: Instant::now(),
            ack_promptly: false,
            bcast_forward: false,
            send_full: true
        }
    }

    fn seen(&mut self) {
        self.last_seen = Instant::now()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Link {
    version: i8,
    iface: i8,
    ack_seq: i8,
    ack_mask: u32,
    drop_rate: i8,
    last_sent_seq: i8,
    send: bool,
    send_at: Instant,
    last_seen: Instant
}

impl Link {
    fn new(iface: i8, seq: i8) -> Link {
        Link {
            version: -1,
            iface: iface,
            ack_seq: seq,
            ack_mask: 0,
            drop_rate: -1,
            last_sent_seq: -1,
            send: false,
            send_at: Instant::now(),
            last_seen: Instant::now(),
        }
    }


    fn schedule(&mut self, time: Duration) {
        self.send = true;
    }

    fn seen(&mut self) {
        self.last_seen = Instant::now()
    }
}


#[derive(Debug, Clone, PartialEq)]
struct Hop {
    cost: u32, 
    edge: EdgeIndex
}

impl Hop {
    fn new(cost: u32, edge: EdgeIndex) -> Hop {
        Hop {
            cost: cost,
            edge: edge
        }
    }
}

impl Eq for Hop { }

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
    link_interval: Duration,
    base_timeout: Duration,
    peers: DiGraph<Peer, Link>,
    next_hop: HashMap<Addr, Hop>,
    local_addrs: HashSet<Addr>,
    dirty: bool
}

impl Table {
    pub fn new(link_interval: Duration, base_timeout: Duration) -> Table {
        Table {
            link_interval: link_interval,
            base_timeout: base_timeout,
            peers: DiGraph::new(),
            next_hop: HashMap::new(),
            local_addrs: HashSet::new(),
            dirty: false
        }
    }

    fn deserialize_link_payload<'b>(buf: &'b [u8]) -> IResult<&[u8], (Addr, Addr, i8, i8, i8, u32, i8)> {
        let (r, _) = try_parse!(buf, tag!([0]));
        let (r, bits) = try_parse!(r, be_u8);
        let flags = match LinkFlags::from_bits(bits) {
            Some(flags) => flags,
            None => return IResult::Error(ErrorKind::Custom(42))
        };
        let (r, rx): (&[u8], Addr) = try_parse!(r, address_parse);
        let (r, version) = try_parse!(r, be_i8);
        let (r, tx): (&[u8], Addr) = if !flags.contains(LINK_NO_PATH) {
            try_parse!(r, address_parse)
        } else {
            (r, ADDR_EMPTY)
        };
        let (r, iface): (&[u8], i8) = if flags.contains(LINK_INTERFACE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        let (r, (ack_seq, ack_mask)) = if flags.contains(LINK_ACK) {
            try_parse!(r, tuple!(be_i8, be_u32))
        } else {
            (r, (-1, 0))
        };
        let (r, drop_rate) = if flags.contains(LINK_DROP_RATE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        IResult::Done(r, (rx, tx, version, iface, ack_seq, ack_mask, drop_rate))
    }

    fn deserialize_link(&mut self, packet: Packet) -> Result<()> {
        let contents = packet.contents()?;
        match Table::deserialize_link_payload(contents) {
            IResult::Done(_, (rx, tx, version, iface, ack_seq, ack_mask, drop_rate)) => {
                self.update_link(rx, tx, version, iface, ack_seq, ack_mask, drop_rate);
                Ok(())
            },
            IResult::Incomplete(needed) => Err(Error::ParseIncomplete(needed)),
            IResult::Error(err) => Err(Error::ParseError(err))
        }
    }

    fn serialize_link<B: BufMut>(link: &Link, rx: &Addr, tx: &Addr, buf: &mut B) -> Result<usize> {
        let mut flags = LinkFlags { bits: 0 };
        if tx == &ADDR_EMPTY {
            flags.insert(LINK_NO_PATH)
        };
        if link.iface >= 0 {
            flags.insert(LINK_INTERFACE)
        };
        if link.ack_seq >= 0 {
            flags.insert(LINK_ACK)
        };
        if link.drop_rate >= 0 {
            flags.insert(LINK_DROP_RATE)
        };
        let before: usize = buf.remaining_mut();
        buf.put_u8(0);
        buf.put_u8(flags.bits);
        buf.put_slice(rx.as_ref());
        buf.put_i8(link.version);
        if tx != &ADDR_EMPTY {
            buf.put_slice(tx.as_ref());
        };
        if link.iface >= 0 {
            buf.put_i8(link.iface);
        };
        if link.ack_seq >= 0 {
            buf.put_i8(link.ack_seq);
            buf.put_u32::<BigEndian>(link.ack_mask);
        };
        if link.drop_rate >= 0 {
            buf.put_i8(link.drop_rate);
        };
        Ok(before - buf.remaining_mut())
    }

    fn link_cost(&self, edge: EdgeReference<Link>) -> Option<u32> {
        let link = edge.weight();
        if link.last_seen + self.base_timeout > Instant::now() {
            if link.drop_rate >= 0 {
                Some(1 / 1 - link.drop_rate as u32 / i8::max_value() as u32)
            } else {
                Some(1)
            }
        } else {
            //self.peers.remove_edge(edge.id());
            None
        }
    }

    fn find_next_hops(&mut self) {
        let mut visited = self.peers.visit_map();
        let mut visit_next = BinaryHeap::new();
        self.next_hop.clear();
        //self.next_hop.insert(ADDR_LOCAL, Hop::new(0, &ADDR_LOCAL, -1));
        //Collect neighbors
        //self.find_neighbors(&mut visited);
        let local_id = self.get_node(&ADDR_LOCAL);
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
                            },
                            Vacant(e) => {
                                e.insert(Hop::new(cost, edge.id()));
                            }
                        };
                    };
                };
            };
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

    fn get_node(&mut self, peer: &Addr) -> NodeIndex {
        for (index, node) in self.peers.raw_nodes().iter().enumerate() {
            if node.weight.addr == *peer {
                return NodeIndex::new(index)
            }
        }
        self.peers.add_node(Peer::new(*peer))
    }

    fn get_peer_mut<A: Into<Addr>>(&mut self, peer: A) -> Option<&mut Peer> {
        let peer_addr = peer.into();
        self.peers.node_weights_mut().find(|p| p.addr == peer_addr)
    }

    fn get_edge(&self, rx: NodeIndex, tx: NodeIndex, iface: i8) -> Option<EdgeIndex> {
        self.peers.edges_directed(rx, Direction::Incoming).find(|e| { 
            let t = e.source();
            t == tx && &self.peers[e.id()].iface == &iface
        }).map(|e| e.id())
    }

    fn get_link_mut(&mut self, rx: NodeIndex, tx: NodeIndex, iface: i8) -> Option<&mut Link> {
        self.get_edge(rx, tx, iface).map(move |e| &mut self.peers[e])
    }

    pub fn insert_local<A: Into<Addr>>(&mut self, addr: A) -> bool {
        self.local_addrs.insert(addr.into())
    }

    pub fn remove_local<A: Into<Addr>>(&mut self, addr: A) -> bool {
        self.local_addrs.remove(&addr.into())
    }

    pub fn is_local<A: Into<Addr>>(&self, addr: A) -> bool {
        self.local_addrs.contains(&addr.into())
    }

    pub fn is_duplicate_frame<A: Into<Addr> + Copy>(&mut self, src: A, iface: i8, seq: i8) -> bool {
        let local_id = self.get_node(&ADDR_LOCAL);
        let index = self.get_node(&src.into());
        if let Some(link) = self.get_link_mut(local_id, index, iface) {
            link.seen();
            if link.ack_seq < 0 {
                link.ack_seq = seq;
                return false;
            }

            if link.ack_seq == seq {
                return true;
            }

            let delta = (link.ack_seq - seq - 1).abs();
            if delta < ACK_WINDOW_FRAME {
                if link.ack_seq > seq {
                    if link.ack_mask.nth_bit_is_set(delta) {
                        return true;
                    } else {
                        link.ack_mask |= 1u32 << delta;
                    }
                } else {
                    link.ack_mask = link.ack_mask << (delta + 1);
                    link.ack_mask |= 1u32 << delta;
                    link.ack_seq = seq;
                }
            } else {
                link.ack_mask = 0;
                link.ack_seq = seq;
            }
            return false
        };
        self.peers.add_edge(index, local_id, Link::new(iface, seq));
        false
    }

    pub fn peer_exists<A: Into<Addr>>(&mut self, peer: A) -> bool {
        self.get_peer_mut(peer).is_some()
    }

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

            let delta = (peer.ack_seq - seq - 1).abs();
            if delta < ACK_WINDOW_PACKET {
                if peer.ack_seq > seq {
                    if peer.ack_mask.nth_bit_is_set(delta) {
                        return true;
                    } else {
                        peer.ack_mask |= 1u64 << delta;
                    }
                } else {
                    peer.ack_mask = peer.ack_mask << (delta + 1);
                    peer.ack_mask |= 1u64 << delta;
                    peer.ack_seq = seq;
                }
            } else {
                peer.ack_mask = 0;
                peer.ack_seq = seq;
            }
        }                
        false
    }

    pub fn update_link<A: Into<Addr> + Copy>(&mut self, rx: A, tx: A, version: i8, iface: i8, ack_seq: i8, ack_mask: u32, drop_rate: i8) {
        let rx_index = self.get_node(&rx.into());
        let tx_index = self.get_node(&tx.into());
        let interval = self.link_interval;
        if let Some(link) = self.get_link_mut(rx_index, tx_index, iface) {
            if version > link.version {
                link.version = version;
                if drop_rate >= 0 {
                    link.drop_rate = drop_rate;
                }
                if link.last_sent_seq >= 0 {
                    let delta = (link.last_sent_seq - ack_seq - 1).abs();
                    if delta < ACK_WINDOW_FRAME && (delta == 0 || ack_mask.nth_bit_is_set(delta)) {
                        link.last_sent_seq = -1;
                    } else if delta <= ACK_WINDOW_MAX {
                        link.schedule(Duration::from_millis(10));
                    }
                }
            }
            link.seen();
            return
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
            link.schedule(interval);
            self.peers.add_edge(tx_index, rx_index, link);
        };
        self.dirty = true;
    }

    pub fn is_reachable<A: Into<Addr>>(&self, p: A) -> bool {
        self.next_hop.get(&p.into()).is_some()
    }

    pub fn next_hop<A: Into<Addr>>(&mut self, peer: A) -> Option<(&Addr, i8)> {
        if self.dirty {
            self.find_next_hops();
        }
        if let Some(&Hop { edge, .. }) = self.next_hop.get(&peer.into()) {
            if let Some((_, target)) = self.peers.edge_endpoints(edge) {
                Some((&self.peers[target].addr, self.peers[edge].iface))
            } else {
                None
            }
        } else {
            None
        }
    }
}

