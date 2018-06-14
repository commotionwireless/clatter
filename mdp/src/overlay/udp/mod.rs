//! Overlay `Interface` for transiting MDP traffic over UDP/IP using Tokio.
//!
//! This contains an implementation of `Interface` and associated primitives that allows for
//! transiting of MDP traffic over UDP, using the [`Tokio`](https://tokio.rs) implementation of UDP sockets.
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::BytesMut;
use futures::prelude::*;
use futures::Sink;
use futures::Stream;
use tokio::net::UdpSocket;

use error::{Error, Result};
use frame::Frame;
use interface::Interface as InterfaceTrait;
use interface::BoxInterface;

const MTU: usize = 1200;

/// The default UDP/IP port for MDP.
pub const DEFAULT_PORT: u16 = 4110;

/// An IPv4 interface.
#[derive(Debug)]
pub struct V4Interface {
    sockets: [UdpSocket; 2],
    next_frame: Option<Frame>,
    toggle: bool,
    seq: i8,
    last_sent_seq: i8,
    rd: BytesMut,
    wr: BytesMut,
}

impl V4Interface {
    fn new(socket: UdpSocket, port: u16) -> Result<V4Interface> {
        match socket.set_broadcast(true) {
            Ok(()) => match UdpSocket::bind(&SocketAddr::new(
                Ipv4Addr::new(255, 255, 255, 255).into(),
                port,
            )) {
                Ok(broadcast) => {
                    broadcast.set_broadcast(true).unwrap();
                    Ok(V4Interface {
                        sockets: [socket, broadcast],
                        next_frame: None,
                        toggle: false,
                        seq: 0,
                        last_sent_seq: 0,
                        rd: BytesMut::with_capacity(MTU),
                        wr: BytesMut::with_capacity(MTU),
                    })
                }
                Err(e) => Err(Error::Io(e)),
            },
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn seq(&self) -> i8 {
        self.seq
    }

    fn next_seq(&mut self) {
        self.last_sent_seq = self.seq;
        if self.seq == <i8>::max_value() || self.seq < 0 {
            self.seq = 0;
        } else {
            self.seq += 1;
        }
    }

    fn next_frame_len(&self) -> usize {
        match self.next_frame {
            Some(ref f) => f.len(),
            None => 0,
        }
    }
}

/// An IPv6 interface.
#[derive(Debug)]
pub struct V6Interface {
    socket: UdpSocket,
    next_frame: Option<Frame>,
    seq: i8,
    last_sent_seq: i8,
    rd: BytesMut,
    wr: BytesMut,
}

impl V6Interface {
    fn new(socket: UdpSocket) -> Result<V6Interface> {
        match socket.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0) {
            Ok(()) => Ok(V6Interface {
                socket: socket,
                next_frame: None,
                seq: 0,
                last_sent_seq: 0,
                rd: BytesMut::with_capacity(MTU),
                wr: BytesMut::with_capacity(MTU),
            }),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn seq(&self) -> i8 {
        self.seq
    }

    fn next_seq(&mut self) {
        self.last_sent_seq = self.seq;
        if self.seq == <i8>::max_value() || self.seq < 0 {
            self.seq = 0;
        } else {
            self.seq += 1;
        }
    }

    fn next_frame_len(&self) -> usize {
        match self.next_frame {
            Some(ref f) => f.len(),
            None => 0,
        }
    }
}

/// An MDP-over-UDP `Interface`.
///
/// This is an `Interface` for transporting MDP traffic over UDP. It takes both IPv4 and IPv6
/// addresses.
#[derive(Debug)]
pub enum Interface {
    V4(V4Interface),
    V6(V6Interface),
}

impl Interface {
    /// Creates a new trait object from an existing `UdpSocket` and port.
    pub fn new(socket: UdpSocket) -> Result<BoxInterface> {
        match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) => {
                let v4 = V4Interface::new(socket, addr.port())?;
                Ok(Box::new(Interface::V4(v4)))
            }
            Ok(SocketAddr::V6(_)) => {
                let v6 = V6Interface::new(socket)?;
                Ok(Box::new(Interface::V6(v6)))
            }
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn decode_frame(&self, n: usize) -> Result<Frame> {
        match *self {
            Interface::V4(ref iface) => Frame::decode(&iface.rd[..n]),
            Interface::V6(ref iface) => Frame::decode(&iface.rd[..n]),
        }
    }

    fn encode_frame(&mut self, frame: Frame) -> Result<Option<Frame>> {
        match *self {
            Interface::V4(ref mut iface) => {
                let len = iface.wr.len();
                if len == 0 {
                    if iface.next_frame.is_some() {
                        //If there's more than one message per frame, they each get a two byte
                        //length field.
                        if iface.next_frame_len() + frame.len() <= MTU + 4 {
                            let mut to_encode = iface.next_frame.take().unwrap();
                            trace!("Encoding frame: {:?}", frame);
                            to_encode.extend(frame);
                            to_encode.header_mut().set_seq(iface.seq());
                            to_encode.encode(&mut iface.wr)?;
                            Ok(None)
                        } else {
                            let mut to_encode = iface.next_frame.take().unwrap();
                            to_encode.header_mut().set_seq(iface.seq());
                            trace!("Encoding frame: {:?}", frame);
                            to_encode.encode(&mut iface.wr)?;
                            Ok(Some(frame))
                        }
                    } else if frame.len() <= MTU {
                        mem::replace(&mut iface.next_frame, Some(frame));
                        trace!("Next frame for encoding is on deck: {:?}", iface.next_frame);
                        Ok(None)
                    } else {
                        Ok(Some(frame))
                    }
                } else if frame.contents().len(frame.header().src()) + len <= MTU {
                    frame
                        .contents()
                        .encode(frame.header().src(), &mut iface.wr)?;
                    Ok(None)
                } else {
                    Ok(Some(frame))
                }
            }
            Interface::V6(ref mut iface) => {
                let len = iface.wr.len();
                if len == 0 {
                    if iface.next_frame.is_some() {
                        //If there's more than one message per frame, they each get a two byte
                        //length field.
                        if iface.next_frame_len() + frame.len() <= MTU + 4 {
                            let mut to_encode = iface.next_frame.take().unwrap();
                            trace!("Encoding frame: {:?}", frame);
                            to_encode.extend(frame);
                            to_encode.header_mut().set_seq(iface.seq());
                            to_encode.encode(&mut iface.wr)?;
                            Ok(None)
                        } else {
                            let mut to_encode = iface.next_frame.take().unwrap();
                            to_encode.header_mut().set_seq(iface.seq());
                            trace!("Encoding frame: {:?}", frame);
                            to_encode.encode(&mut iface.wr)?;
                            Ok(Some(frame))
                        }
                    } else if frame.len() <= MTU {
                        mem::replace(&mut iface.next_frame, Some(frame));
                        Ok(None)
                    } else {
                        Ok(Some(frame))
                    }
                } else if frame.contents().len(frame.header().src()) + len <= MTU {
                    frame
                        .contents()
                        .encode(frame.header().src(), &mut iface.wr)?;
                    Ok(None)
                } else {
                    Ok(Some(frame))
                }
            }
        }
    }

    fn is_sent(&self) -> bool {
        match *self {
            Interface::V4(ref iface) => iface.next_frame.is_none() && iface.wr.is_empty(),
            Interface::V6(ref iface) => iface.next_frame.is_none() && iface.wr.is_empty(),
        }
    }

    fn recv_from(&mut self) -> io::Result<(usize, SocketAddr)> {
        match *self {
            Interface::V4(ref mut iface) => {
                trace!("recv_from: attempting to read from socket.");
                iface.sockets[1].recv_from(&mut iface.rd)
            }
            Interface::V6(ref mut iface) => {
                trace!("recv_from: attempting to read from socket.");
                iface.socket.recv_from(&mut iface.rd)
            }
        }
    }

    fn send_to(&mut self) -> Result<Option<usize>> {
        match *self {
            Interface::V4(ref mut iface) => {
                let local_addr = iface.sockets[1].local_addr()?;
                let bcast =
                    SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), local_addr.port());
                if iface.next_frame.is_some() {
                    let next = iface.next_frame.take().unwrap();
                    next.encode(&mut iface.wr)?;
                }
                match iface.sockets[0].send_to(&iface.wr, &bcast) {
                    Ok(n) => {
                        debug!("Sent {} bytes to {}.", n, &bcast);
                        let sent_all = n == iface.wr.len();
                        iface.next_frame.take();
                        iface.wr.clear();
                        if sent_all {
                            iface.next_seq();
                            Ok(Some(n))
                        } else {
                            Err(Error::UdpIncompleteSend(n))
                        }
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            debug!("Socket would block.");
                            Ok(None)
                        } else {
                            debug!("Error sending to socket.");
                            Err(Error::Io(e))
                        }
                    }
                }
            }
            Interface::V6(ref mut iface) => {
                let local_addr = iface.socket.local_addr()?;
                let mcast = SocketAddr::new(
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).into(),
                    local_addr.port(),
                );
                if iface.next_frame.is_some() {
                    let next = iface.next_frame.take().unwrap();
                    next.encode(&mut iface.wr)?;
                }
                match iface.socket.send_to(&iface.wr, &mcast) {
                    Ok(n) => {
                        debug!("Sent {} bytes to {}.", n, &mcast);
                        let sent_all = n == iface.wr.len();
                        iface.next_frame.take();
                        iface.wr.clear();
                        if sent_all {
                            iface.next_seq();
                            Ok(Some(n))
                        } else {
                            Err(Error::UdpIncompleteSend(n))
                        }
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            Ok(None)
                        } else {
                            Err(Error::Io(e))
                        }
                    }
                }
            }
        }
    }

    pub fn close(&mut self) -> Poll<(), Error> {
        try_ready!(self.poll_complete());

        Ok(().into())
    }
}

impl InterfaceTrait for Interface {
    fn last_sent_seq(&self) -> i8 {
        match *self {
            Interface::V4(ref iface) => iface.last_sent_seq,
            Interface::V6(ref iface) => iface.last_sent_seq,
        }
    }
}

impl From<UdpSocket> for BoxInterface {
    fn from(socket: UdpSocket) -> Self {
        match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) => {
                let v4 = V4Interface::new(socket, addr.port()).expect("Failed to create interface.");
                Box::new(Interface::V4(v4))
            }
            Ok(SocketAddr::V6(_)) => {
                let v6 = V6Interface::new(socket).expect("Failed to create interface.");
                Box::new(Interface::V6(v6))
            }
            _ => panic!("Failed to create interface.")
        }
    }
}



impl Stream for Interface {
    type Item = Frame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (n, addr) = try_nb!(self.recv_from());
        debug!("Read {} bytes from {}.", n, addr);
        match self.decode_frame(n) {
            Ok(frame) => {
                debug!("Decoded frame from {}.", addr);
                Ok(Async::Ready(Some(frame)))
            }
            Err(e) => {
                error!("Error decoding frame from {}: {}", addr, e);
                Ok(Async::NotReady)
            }
        }
    }
}

impl Sink for Interface {
    type SinkItem = Frame;
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let frame = match self.encode_frame(item) {
            Ok(None) => {
                trace!("start_send: Successfully encoded frame.");
                return Ok(AsyncSink::Ready);
            }
            Ok(Some(frame)) => frame,
            Err(e) => return Err(e),
        };
        if !self.is_sent() {
            match self.poll_complete()? {
                Async::Ready(()) => (),
                Async::NotReady => return Ok(AsyncSink::NotReady(frame)),
            }
        }
        match self.encode_frame(frame) {
            Ok(None) => Ok(AsyncSink::Ready),
            Ok(Some(frame)) => Ok(AsyncSink::NotReady(frame)),
            Err(e) => Err(e),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        if self.is_sent() {
            trace!("iface poll_complete: already sent");
            Ok(Async::Ready(()))
        } else {
            self.send_to().map(|n| {
                if n.is_some() {
                    trace!("iface poll_complete: sent successfully");
                    Async::Ready(())
                } else {
                    trace!("iface poll_complete: not sent successfully");
                    Async::NotReady
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn bind_interface() {
        let addr: SocketAddr = "127.0.0.1:4110".parse().unwrap();
        let s = UdpSocket::bind(&addr).unwrap();
        Interface::new(s).unwrap();
    }
}
