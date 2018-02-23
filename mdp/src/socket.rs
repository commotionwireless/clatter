//! Socket primitives for working with MDP.
//!
//! The `Socket` type provides the equivalent of a UDP socket, except over an MDP virtual overlay
//! network. It's provided by and associated with a particular instance of Protocol. MDP has its
//! own address and port space that is distinct from whatever IP-based or other network it happens
//! to be running on, but provides an interface similar to other socket libraries. Multiple sockets
//! can be associated with a single instance of `Protocol`, using the same or different MDP addresses
//! (each of which represents an elliptic-curve public key), but only one socket can be bound to
//! any particular address/port combination at one time.
use std::vec::Vec;
use std::sync::Arc;
use std::sync::Mutex;
use futures::prelude::*;
use futures::sync::mpsc::UnboundedReceiver;
use addr::{Addr, LocalAddr, SocketAddr, ADDR_EMPTY};
use error::Error;
use packet::Packet;
use protocol::ProtocolInfo;
use qos;
pub use packet::State;
pub use packet::TTL_MAX;
pub use packet::QOS_DEFAULT;
pub use qos::Class;

/// The default TTL value for MDP sockets.
pub const TTL_DEFAULT: u8 = 31;

/// A virtual socket on an MDP overlay network.
///
/// Provided by the bind method on `Protocol`, `SocketAddr` implements both `Futures::Stream` and
/// `Futures::Sink` for bidirectional asynchronous handling of messages over the network. The Socket
/// is bound to an MDP SocketAddr, which is comprised of both a public key and a 32-bit MDP port
/// number (which is only meaningful within the overlay network and is distinct from an IP port).
///
/// # Example
/// 
/// Bind MDP socket on port 5000 using the default address and a second socket on port 5001 using a
/// different address.
/// ```
/// use mdp::addr::LocalAddr;
/// use mdp::protocol::Protocol;
///
/// let local_addr = LocalAddr::new();
/// let proto = Protocol::new(&local_addr);
/// let socket0 = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
/// let new_addr = LocalAddr::new();
/// let socket1= proto.bind(&new_addr, 5001).expect("Failed to bind MDP socket.");
/// ```
pub struct Socket {
    proto: Arc<Mutex<ProtocolInfo>>,
    incoming: UnboundedReceiver<Packet>,
    index: usize,
    addr: LocalAddr,
    port: u32,
    qos: qos::Class,
    ttl: u8,
}

impl Socket {
    pub(crate) fn new(
        proto: &Arc<Mutex<ProtocolInfo>>,
        incoming: UnboundedReceiver<Packet>,
        index: usize,
        addr: &LocalAddr,
        port: u32,
    ) -> Socket {
        Socket {
            proto: proto.clone(),
            incoming: incoming,
            index: index,
            addr: addr.clone(),
            port: port,
            qos: qos::Class::Ordinary,
            ttl: TTL_DEFAULT,
        }
    }

    /// Get the time-to-live value for this socket.
    ///
    /// For more information about this option, see ['set_ttl'][link]
    ///
    /// [link]: #method.set_ttl
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::{Socket, TTL_DEFAULT};
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// assert_eq!(socket.ttl(), TTL_DEFAULT);
    /// ```
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Set the time-to-live value for this socket.
    ///
    /// This sets the TTL value that is used for every message sent from this socket. The maximum
    /// TTL value for MDP is 31, so any value higher than 31 is automatically set to the maximum.
    ///
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::Socket;
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let mut socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// socket.set_ttl(6);
    /// assert_eq!(socket.ttl(), 6);
    /// ```
    pub fn set_ttl(&mut self, ttl: u8) {
        if ttl > TTL_MAX {
            self.ttl = TTL_MAX
        } else {
            self.ttl = ttl
        }
    }

    /// Get the default Quality-of-Service class for this socket.
    ///
    /// For more information about this option, see [`set_qos`][link].
    ///
    /// [link]: #method.set_qos
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::{Socket, QOS_DEFAULT};
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// assert_eq!(socket.qos(), QOS_DEFAULT);
    /// ```
    pub fn qos(&self) -> qos::Class {
        self.qos
    }

    /// Set the default Quality-of-Service class for this socket.
    ///
    /// This sets the Quality-of-Service class that every message sent from this socket is sorted
    /// into. This affects scheduling and timeouts of outgoing messages.
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::{Class, Socket};
    /// # fn main() {
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let mut socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// socket.set_qos(Class::Management);
    /// assert_eq!(socket.qos(), Class::Management);
    /// # }
    /// ```
    pub fn set_qos(&mut self, class: qos::Class) {
        self.qos = class
    }

    /// Get the value of the broadcast flag for this socket.
    ///
    /// For more information about this option, see [`set_broadcast`][link].
    ///
    /// [link]: #method.set_broadcast
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::Socket;
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// assert_eq!(socket.broadcast(), false);
    /// ```
    pub fn broadcast(&self) -> bool {
        let mut proto = self.proto.lock().unwrap();
        if let Some(ref info) = proto.socket_info(self.index) {
            info.broadcast()
        } else {
            error!("MDP Protocol is unaware of socket #{}!", self.index);
            false
        }
    }

    /// Set the broadcast flag for this socket.
    ///
    /// When set, this Socket will receive MDP broadcast messages sent to its port. Defaults to
    /// `false`.
    /// # Example
    /// ```
    /// use mdp::addr::LocalAddr;
    /// use mdp::protocol::Protocol;
    /// use mdp::socket::Socket;
    ///
    /// let local_addr = LocalAddr::new();
    /// let mut proto = Protocol::new(&local_addr);
    /// let mut socket = proto.bind(&local_addr, 5000).expect("Failed to bind MDP socket.");
    /// socket.set_broadcast(true);
    /// assert_eq!(socket.broadcast(), true);
    /// ```
    pub fn set_broadcast(&mut self, on: bool) {
        let mut proto = self.proto.lock().unwrap();
        if let Some(ref mut info) = proto.socket_info(self.index) {
            info.set_broadcast(on)
        } else {
            error!("MDP Protocol is unaware of socket #{}!", self.index);
        }
    }

    pub(crate) fn proto(&self) -> &Arc<Mutex<ProtocolInfo>> {
        &self.proto
    }
}

impl Stream for Socket {
    type Item = (Vec<u8>, SocketAddr, State);
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        while let Some(mut packet) =
            try_ready!(self.incoming.poll().map_err(|_| Error::InvalidSocket))
        {
            trace!("Received message: {:?}", packet);
            let state = packet.state();
            match state {
                State::Plain => {
                    return Ok(Async::Ready(Some((
                        packet.contents().unwrap().to_vec(),
                        (*packet.src(), packet.src_port().unwrap()).into(),
                        packet.state(),
                    ))))
                }
                State::Signed => {
                    packet.verify()?;
                    return Ok(Async::Ready(Some((
                        packet.contents().unwrap().to_vec(),
                        (*packet.src(), packet.src_port().unwrap()).into(),
                        packet.state(),
                    ))));
                }
                State::Encrypted => {
                    packet.decrypt(&self.addr)?;
                    if let Some(dst_port) = packet.dst_port() {
                        if dst_port == self.port {
                            return Ok(Async::Ready(Some((
                                packet.contents().unwrap().to_vec(),
                                (*packet.src(), packet.src_port().unwrap()).into(),
                                packet.state(),
                            ))));
                        } else {
                            debug!("Decrypted message for a different socket, requeueing it.");
                            let mut proto = self.proto.lock().unwrap();
                            proto.try_send(packet)?;
                            //proto.handle_packet(packet, None);
                            continue;
                        }
                    }
                }
            }
        }
        Ok(Async::NotReady)
    }
}

impl Sink for Socket {
    type SinkItem = (Vec<u8>, SocketAddr, State);
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let mut proto = self.proto.lock().unwrap();
        let seq = match proto.socket_info(self.index) {
            Some(s) => s.next_seq(),
            None => -1,
        };
        let addr = Addr::from(&self.addr);
        let mut packet = Packet::new(
            (addr, self.port).into(),
            item.1,
            ADDR_EMPTY,
            self.ttl,
            self.qos,
            seq,
            false,
            item.0.as_ref(),
        );
        match item.2 {
            State::Signed => {
                packet.sign(&self.addr)?;
            }
            State::Encrypted => {
                packet.encrypt(&self.addr)?;
            }
            State::Plain => (),
        }

        trace!("socket start_send: try_send #1");
        let packet = match proto.try_send(packet)? {
            Some(packet) => packet,
            None => return Ok(AsyncSink::Ready),
        };

        if !proto.poll_interfaces_complete()? {
            trace!("socket start_send: try_send #2");
            match proto.try_send(packet)? {
                Some(_) => Ok(AsyncSink::NotReady(item)),
                None => Ok(AsyncSink::Ready),
            }
        } else {
            trace!("socket start_send: ready");
            Ok(AsyncSink::Ready)
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        let mut proto = self.proto.lock().unwrap();
        if !proto.poll_interfaces_complete()? {
            trace!("socket poll_complete: not all interfaces complete");
            Ok(Async::NotReady)
        } else {
            trace!("socket poll_complete: all interfaces complete");
            Ok(Async::Ready(()))
        }
    }
}
