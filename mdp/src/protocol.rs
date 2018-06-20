//! The primary state machine for the MDP protocol and its associated methods. It represents a
//! single instance of MDP.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    vec::{IntoIter, Vec}
};
use bytes::BytesMut;
use futures::{
    prelude::*,
    Async,
    AsyncSink,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender}
};
use tokio_timer::Interval;
use stable_vec::StableVec;

use addr::{Addr, LocalAddr, SocketAddr, ADDR_BROADCAST, ADDR_EMPTY};
use broadcast;
use error::{Error, Result};
use frame::Frame;
use interface::{BoxInterface, Interface};
use message::Message;
use qos::{self, QueuedState};
use routing;
use socket::Socket;

/// The default MDP port for the linkstate routing service.
pub const PORT_LINKSTATE: u32 = 2;
const SEND_DELAY_MS: u64 = 5;

/// A future for running the state machine.
///
/// This future is meant to be run by an event loop, such as Tokio's Reactor, or Futures CpuPool.
/// It does not return. Ticker is returned by the Protocol object's run() method.
pub struct Ticker {
    interval: Interval,
    proto: Arc<Mutex<ProtocolInfo>>,
}

impl Future for Ticker {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let &mut Ticker {
            ref mut interval,
            ref proto,
        } = self;
        interval
            .for_each(|_| {
                let mut proto = proto.lock().unwrap();
                for frame in proto.poll_interfaces() {
                    let tx = *frame.header().tx();
                    let iface = frame.header().iface();
                    proto.routes.seen_tx(&tx, iface);
                    for mut m in frame {
                        m.ttl_decrement();
                        let _ = proto
                            .handle_message(m, Some(&tx))
                            .map_err(|e| error!("Error handling message: {:?}", e));
                    }
                }
                let _ = proto
                    .tick_linkstate()
                    .map_err(|e| error!("Error sending linkstate: {:?}", e));
                let _ = proto
                    .flush_outgoing()
                    .map_err(|e| error!("Error flushing outgoing queue: {:?}", e));
                let _ = proto
                    .poll_interfaces_complete()
                    .map_err(|e| error!("Error polling interfaces for completion: {:?}", e));
                trace!("TICK!");
                Ok(())
            })
            .poll()
            .map_err(|_| ())
    }
}

#[derive(Debug)]
struct InterfaceInfo {
    iface: Box<Interface<Item = Frame, Error = Error, SinkItem = Frame, SinkError = Error>>,
}

#[derive(Debug, Clone)]
pub(crate) struct SocketInfo {
    port: u32,
    broadcast: bool,
    seq: i8,
    incoming: UnboundedSender<Message>,
}

impl SocketInfo {
    fn new(port: u32) -> (SocketInfo, UnboundedReceiver<Message>) {
        let (sender, receiver) = mpsc::unbounded();
        let info = SocketInfo {
            port: port,
            broadcast: false,
            seq: 0,
            incoming: sender,
        };
        (info, receiver)
    }

    pub(crate) fn next_seq(&mut self) -> i8 {
        let ret = self.seq;
        if ret == <i8>::max_value() || ret < 0 {
            self.seq = 0;
        } else {
            self.seq += 1;
        }
        ret
    }

    pub(crate) fn broadcast(&self) -> bool {
        self.broadcast
    }

    pub(crate) fn set_broadcast(&mut self, on: bool) {
        self.broadcast = on
    }
}

/// The primary state machine for MDP.
///
/// A Protocol object holds the state machine for an instance of MDP. It holds the list of
/// associated interfaces and sockets, manages the flow of incoming and outgoing messages, and
/// contains the routing table.
pub struct Protocol(Arc<Mutex<ProtocolInfo>>);

impl Protocol {
    /// Creates a new instance of Protocol.
    ///
    /// Takes a default address which is used for encoding Frames.
    ///
    /// # Examples
    ///
    /// Create a new instance of Protocol.
    ///
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    ///
    /// let local_addr = LocalAddr::new();
    /// let protocol = Protocol::new(&local_addr);
    /// ```
    pub fn new<A: Into<Addr>>(default_addr: A) -> Protocol {
        Protocol(Arc::new(Mutex::new(ProtocolInfo::new(&default_addr
            .into()))))
    }

    /// Registers an Interface with this instance of Protocol.
    ///
    /// A Protocol object needs to be associated with one or more Interfaces over which to route
    /// traffic. You can use this function to add an instance of Interface to the state machine. It
    /// returns an integer representing the unique internal identifier used for this interface.
    ///
    /// # Examples
    ///
    /// Bind a UDP socket, turn it into an Interface, and then register it with a new instance of
    /// Protocol.
    ///
    /// ```no_run
    /// extern crate mdp;
    /// extern crate tokio;
    /// use std::net::SocketAddr;
    /// use tokio::net::UdpSocket;
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::overlay::udp::Interface;
    /// # fn main() {
    /// let ip_address: SocketAddr = "0.0.0.0:4110".parse().unwrap();
    /// let udp_socket = UdpSocket::bind(&ip_address).expect("Failed to bind UdpSocket.");
    /// let interface = Interface::new(udp_socket).unwrap();
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// proto.interface(interface);
    /// # }
    /// ```
    pub fn interface(&mut self, iface: BoxInterface) -> usize {
        let mut proto = self.0.lock().unwrap();
        let id = proto.ifaces.push(InterfaceInfo { iface: iface });
        info!("Adding interface #{}.", id);
        id
    }

    /// Binds a new Socket to this instance of Protocol.
    ///
    /// Returns a new instance of Socket, associated with this Protocol object and bound to the
    /// specified LocalAddr and port. Each Socket is a Futures transport implementing Sink and
    /// Stream for full duplex asynchronous communication over the MDP encrypted overlay network.
    ///
    /// # Examples
    ///
    /// Create a new socket bound to MDP port 5000.
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP Socket.");
    /// ```
    pub fn bind<'a>(&mut self, addr: &'a LocalAddr, port: u32) -> Result<Socket> {
        let mdp_addr: Addr = addr.into();
        let s_addr: SocketAddr = (mdp_addr, port).into();
        let mut proto = self.0.lock().unwrap();
        let bound = proto.is_bound(&s_addr);
        match bound {
            Some(bound) if bound => return Err(Error::AddrAlreadyInUse(s_addr)),
            _ => {
                proto.routes.insert_local(&mdp_addr);
                proto.socket_indices.insert(mdp_addr, Vec::new());
            }
        }
        let (info, incoming) = SocketInfo::new(port);
        let index = proto.sockets.push(info);
        let v = proto.socket_indices.get_mut(&mdp_addr).unwrap();
        v.push(index);
        info!(
            "Binding new MDP socket #{} on address {:?} and port {}.",
            index, addr, port
        );
        Ok(Socket::new(&self.0, incoming, index, addr, port))
    }

    /// Returns a future that ticks forward the Protocol state machine at the specified interval.
    ///
    /// Takes a Duration and returns a Ticker future that runs the Protocol state machine at the
    /// specified interval.
    ///
    /// # Examples
    ///
    /// Tick-over the state machine every 100 milliseconds on the current thread using the Tokio
    /// current_thread executor.
    ///
    /// ```no_run
    /// extern crate futures;
    /// extern crate tokio;
    /// extern crate mdp;
    /// use std::time::Duration;
    /// use futures::Future;
    /// use tokio::executor::current_thread;
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// # fn main() {
    /// let local_addr = LocalAddr::new();
    /// let proto = Protocol::new(&local_addr);
    /// 
    /// current_thread::run(|_| {
    ///     current_thread::spawn(proto.run(Duration::from_millis(100)).then(|_| Ok(())));
    /// });
    /// # }
    /// ```
    pub fn run(&self, tick: Duration) -> Ticker {
        info!("Running MDP.");
        Ticker {
            interval: Interval::new(Instant::now(), tick),
            proto: self.0.clone(),
        }
    }
}

pub(crate) struct ProtocolInfo {
    ifaces: StableVec<InterfaceInfo>,
    sockets: StableVec<SocketInfo>,
    socket_indices: HashMap<Addr, Vec<usize>>,
    broadcast_ids: broadcast::Window,
    outgoing: qos::Queue,
    routes: routing::Table,
    default_addr: Addr,
}

impl ProtocolInfo {
    pub fn new(default_addr: &Addr) -> ProtocolInfo {
        ProtocolInfo {
            ifaces: StableVec::new(),
            sockets: StableVec::new(),
            socket_indices: HashMap::new(),
            broadcast_ids: broadcast::Window::new(32),
            outgoing: qos::Queue::new(),
            routes: routing::Table::new(default_addr, Duration::from_millis(200)),
            default_addr: *default_addr,
        }
    }

    fn is_bound(&self, dst: &SocketAddr) -> Option<bool> {
        if let Some(indices) = self.socket_indices.get(dst.addr()) {
            for i in indices {
                if let Some(socket) = self.sockets.get(*i) {
                    if socket.port == dst.port() {
                        return Some(true);
                    }
                }
            }
            Some(false)
        } else {
            None
        }
    }

    pub fn poll_interfaces(&mut self) -> IntoIter<Frame> {
        let mut frames = vec![];
        let interfaces = self.ifaces.iter_mut().enumerate();
        for (index, info) in interfaces {
            debug!("Polling interface {}.", index);
            while let Ok(Async::Ready(Some(frame))) = info.iface.poll() {
                let tx = *frame.header().tx();
                if tx == self.default_addr {
                    debug!("Dropping frame originating from us.");
                    continue;
                }
                if !self.routes.is_duplicate_frame(
                    tx,
                    frame.header().iface(),
                    frame.header().seq(),
                ) {
                    trace!("Found new frame!");
                    frames.push(frame);
                }
            }
        }
        frames.into_iter()
    }

    pub fn poll_interfaces_complete(&mut self) -> Result<bool> {
        let mut interfaces = self.ifaces.iter_mut();
        let mut all_complete = true;
        while let Some(info) = interfaces.next() {
            if let Async::NotReady = info.iface.poll_complete()? {
                all_complete = false;
            }
        }
        Ok(all_complete)
    }

    fn tick_linkstate(&mut self) -> Result<()> {
        let &mut ProtocolInfo {
            ref mut routes,
            ref mut outgoing,
            ref default_addr,
            ..
        } = self;
        let mut buf = BytesMut::new();
        let now = Instant::now();
        if *routes.local_last_sent() + Duration::from_millis(routing::LINKSTATE_DELAY_MS) <= now {
            debug!("Sending linkstate updates for local addresses.");
            for addr in routes.local_addrs().iter() {
                if addr != default_addr {
                    let _ = routing::Link::new(-1, -1)
                        .encode(addr, default_addr, &mut buf)
                        .map_err(|e| error!("Error encoding linkstate message: {:?}", e));
                } else {
                    let _ = routing::Link::new(-1, -1)
                        .encode(addr, &ADDR_EMPTY, &mut buf)
                        .map_err(|e| error!("Error encoding linkstate message: {:?}", e));
                }
            }
            routes.set_local_last_sent(now);
        }
        routes.walk_links(|(tx, rx, link)| {
            debug!("Checking link from {:?} to {:?}.", tx, rx);
            if link.is_sendable() {
                if rx == &ADDR_EMPTY {
                    let _ = link.encode(default_addr, tx, &mut buf)
                        .map_err(|e| error!("Error encoding linkstate message: {:?}", e));
                } else {
                    let _ = link.encode(rx, tx, &mut buf)
                        .map_err(|e| error!("Error encoding linkstate message: {:?}", e));
                }
                link.schedule(Duration::from_millis(routing::LINKSTATE_DELAY_MS));
            }
        });
        if !buf.is_empty() {
            let message = Message::new(
                (ADDR_EMPTY, PORT_LINKSTATE),
                (ADDR_BROADCAST, PORT_LINKSTATE),
                ADDR_EMPTY,
                1,
                qos::Class::Management,
                -1,
                false,
                &mut buf,
            );
            outgoing.schedule(message, -1, SEND_DELAY_MS)?;
        }
        Ok(())
    }

    fn send_via(&mut self, iface: i8, message: Message) -> Result<Option<Message>> {
        let default_addr = self.default_addr;
        if iface == -1 {
            let mut any_sent = false;
            self.ifaces
                .iter_mut()
                .enumerate()
                .for_each(|(i, ref mut info)| {
                    let mut message = message.clone();
                    if message.src() == &ADDR_EMPTY {
                        trace!("Setting empty message src to default tx.");
                        message.set_src(&default_addr)
                    }
                    if let Ok(AsyncSink::Ready) =
                        info.iface
                            .start_send(Frame::encap(message, default_addr, i as i8, -1))
                    {
                        any_sent = true;
                    }
                });
            if !any_sent {
                Ok(Some(message))
            } else {
                Ok(None)
            }
        } else if let Some(ref mut info) = self.ifaces.get_mut(iface as usize) {
            match info.iface
                .start_send(Frame::encap(message, default_addr, iface, -1))
            {
                Ok(AsyncSink::Ready) => Ok(None),
                Ok(AsyncSink::NotReady(frame)) => {
                    if let Some(msg) = frame.into_iter().next() {
                        Ok(Some(msg))
                    } else {
                        unreachable!();
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            Err(Error::InvalidInterface)
        }
    }

    fn handle_message(
        &mut self,
        mut message: Message,
        tx: Option<&Addr>,
    ) -> Result<Option<Message>> {
        let local = tx.is_none();
        let src = *message.src();
        let seq = message.seq();
        if !local && self.routes.is_duplicate_message(src, seq) {
            debug!("Dropping duplicate message #{} from {:?}.", seq, src);
            return Ok(None);
        }
        let dst = *message.dst();
        let ttl = message.ttl();
        if dst == ADDR_BROADCAST {
            trace!("Handling broadcast message.");
            //is a broadcast message
            let bid = *message.bid();
            if !self.broadcast_ids.recent(&bid) {
                if let Some(port) = message.dst_port() {
                    debug!(
                        "Handling non-duplicate broadcast message ID# {:?} for port {}.",
                        bid, port
                    );
                    if !message.is_local() {
                        trace!("Searching for local broadcast sockets.");
                        for s in &mut self.sockets {
                            if s.broadcast && s.port == port {
                                debug!("Delivering broadcast message to port {}.", port);
                                let _ = s.incoming.unbounded_send(message.clone()).map_err(|e| {
                                    error!("Error sending message to socket: {:?}", e)
                                });
                            }
                        }
                    }
                } else {
                    error!("Received an encrypted or malformed broadcast message, dropping.");
                    return Ok(None);
                }
                if ttl >= 1 {
                    if let Some(tx) = tx {
                        if self.routes.forward_broadcasts(tx) {
                            debug!("Forwarding broadcast message ID# {:?}.", bid);
                            self.outgoing.schedule(message, -1, SEND_DELAY_MS)?;
                            Ok(None)
                        } else {
                            debug!("We are not currently forwarding broadcasts for {:?}, dropping message.", &tx);
                            Ok(None)
                        }
                    } else {
                        debug!("Sending broadcast message ID# {:?}.", bid);
                        self.outgoing.schedule(message, -1, SEND_DELAY_MS)?;
                        Ok(None)
                    }
                } else {
                    debug!("Not forwarding broadcast message with ttl < 1.");
                    Ok(None)
                }
            } else {
                debug!("Dropping recently seen broadcast message ID# {:?}.", &bid);
                Ok(None)
            }
        } else if self.routes.is_local(&dst) {
            trace!("Handling message for local destination.");
            if let Some(indices) = self.socket_indices.get_mut(&dst) {
                match message.dst_port() {
                    Some(port) => for i in indices.iter() {
                        if let Some(ref mut s) = self.sockets.get_mut(*i) {
                            if port == s.port {
                                debug!(
                                    "Received message for local address {:?} on port {}.",
                                    src, port
                                );
                                let _ = s.incoming.unbounded_send(message).map_err(|e| {
                                    error!("Error sending message to socket: {:?}", e)
                                });
                                return Ok(None);
                            }
                        }
                    },
                    None => {
                        //message isn't decrypted, pass it off to the first socket we can to decrypt
                        if let Some(ref mut s) = self.sockets.get_mut(indices[0]) {
                            debug!("Received message for local address {:?}, sending to port {} for decryption.", src, s.port);
                            let _ = s.incoming
                                .unbounded_send(message)
                                .map_err(|e| error!("Error sending message to socket: {:?}", e));
                        }
                    }
                }
                Ok(None)
            } else {
                error!("Inconsistent protocol state, no such socket exists!");
                Ok(None)
            }
        } else {
            trace!("Forwarding message to remote destination(s).");
            if ttl >= 1 {
                if self.routes.is_dirty() {
                    self.routes.find_next_hops();
                }
                let rx = self.routes.next_hop(message.dst());
                if let Some((next_hop, iface)) = rx {
                    message.set_rx(&next_hop);
                    self.outgoing.schedule(message, iface, SEND_DELAY_MS)?;
                    Ok(None)
                } else {
                    debug!("Dropping message without valid receiver.");
                    Ok(None)
                }
            } else {
                debug!("Dropping message {} for peer {:?}.", seq, src);
                Ok(None)
            }
        }
        //drop
    }

    fn flush_outgoing(&mut self) -> Result<Option<Message>> {
        trace!("Outgoing queue length: {}", self.outgoing.len());
        while let Some((mut msg, info)) = self.outgoing.next() {
            trace!("Popping outgoing queue.");
            match *info.state() {
                QueuedState::Unsent(iface) => {
                    trace!(
                        "Found unsent message {:?}, sending via interfaces #{}.",
                        msg,
                        iface
                    );
                    let resend = msg.clone();
                    match self.send_via(iface, msg) {
                        Ok(None) => {
                            if iface == -1 {
                                for info in self.ifaces.iter() {
                                    let seq = info.iface.last_sent_seq();
                                    trace!("seq #: {}", seq);
                                    if seq >= 0 {
                                        let resend = resend.clone();
                                        if resend.dst() != &ADDR_BROADCAST {
                                            let rx = *resend.rx();
                                            let resend_delay = self.routes.resend_delay(&rx);
                                            self.outgoing.reschedule(
                                                resend,
                                                resend_delay,
                                                seq,
                                                vec![rx],
                                            )?;
                                        } else if let Some(neighbors) =
                                            self.routes.get_neighbors(iface)
                                        {
                                            let resend_delay =
                                                self.routes.resend_delay(&neighbors[0]);
                                            self.outgoing.reschedule(
                                                resend,
                                                resend_delay,
                                                seq,
                                                neighbors,
                                            )?;
                                        }
                                    }
                                }
                            } else {
                                let seq = match self.ifaces.get(iface as usize) {
                                    Some(info) => info.iface.last_sent_seq(),
                                    None => -1,
                                };
                                trace!("seq #: {}", seq);
                                if seq >= 0 {
                                    if resend.dst() != &ADDR_BROADCAST {
                                        let rx = *resend.rx();
                                        let resend_delay = self.routes.resend_delay(&rx);
                                        self.outgoing.reschedule(
                                            resend,
                                            resend_delay,
                                            seq,
                                            vec![rx],
                                        )?;
                                    } else if let Some(neighbors) = self.routes.get_neighbors(iface)
                                    {
                                        let resend_delay = self.routes.resend_delay(&neighbors[0]);
                                        self.outgoing.reschedule(
                                            resend,
                                            resend_delay,
                                            seq,
                                            neighbors,
                                        )?;
                                    }
                                }
                            }
                        }
                        Ok(Some(msg)) => return Ok(Some(msg)),
                        Err(e) => return Err(e),
                    }
                }
                QueuedState::Sent { .. } => {
                    let rx = self.routes.next_hop(msg.dst());
                    if let Some((next_hop, iface)) = rx {
                        trace!(
                            "Found sent message {:?}, resending via interfaces #{}.",
                            msg,
                            iface
                        );
                        msg.set_rx(&next_hop);
                        let resend = msg.clone();
                        match self.send_via(iface, msg) {
                            Ok(None) => {
                                let seq = match self.ifaces.get(iface as usize) {
                                    Some(info) => info.iface.last_sent_seq(),
                                    None => -1,
                                };
                                if seq >= 0 {
                                    let rx = *resend.rx();
                                    if rx != ADDR_BROADCAST {
                                        let resend_delay = self.routes.resend_delay(&rx);
                                        self.outgoing.reschedule(
                                            resend,
                                            resend_delay,
                                            seq,
                                            vec![rx],
                                        )?;
                                    } else if let Some(neighbors) = self.routes.get_neighbors(iface)
                                    {
                                        let resend_delay = self.routes.resend_delay(&neighbors[0]);
                                        self.outgoing.reschedule(
                                            resend,
                                            resend_delay,
                                            seq,
                                            neighbors,
                                        )?;
                                    }
                                }
                            }
                            Ok(Some(msg)) => return Ok(Some(msg)),
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }
        debug!("No more messages queued for sending.");
        Ok(None)
    }

    pub fn try_send(&mut self, message: Message) -> Result<Option<Message>> {
        self.handle_message(message, None)
    }

    pub(crate) fn socket_info(&mut self, id: usize) -> Option<&mut SocketInfo> {
        self.sockets.get_mut(id)
    }

    pub(crate) fn routes_mut(&mut self) -> &mut routing::Table {
        &mut self.routes
    }

    pub(crate) fn outgoing_mut(&mut self) -> &mut qos::Queue {
        &mut self.outgoing
    }
}
