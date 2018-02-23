//! The Mesh Streaming Protocol
//!
//! `MSP` is an analogue of TCP on a traditional IP network, except operating over an encrypted
//! overlay network addressed by elliptic-curve public keys. MSP operates on top of `MDP`, but
//! provides a connection-oriented interface and in-order reliability. `MSP` provides a
//! Futures-based `Stream` and `Sink` interface, but does not currently provide a continuous byte
//! stream; this may be added in the future by providing an internally buffered version.
//!
#[macro_use]
extern crate bitflags;
extern crate bytes;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate mdp;
#[macro_use]
extern crate nom;

mod error;

use std::cmp::Ordering;
use std::default::Default;
use std::mem;
use std::time::{Duration, Instant};
use std::vec::Vec;

use bytes::{BigEndian, BufMut};
use futures::prelude::*;
use futures::{Sink, Stream};
use nom::{IResult, be_u16, be_u8};

use mdp::addr::{ADDR_EMPTY, SocketAddr};
use mdp::socket::State;
use mdp::socket::Socket as MdpSocket;

use error::{Error, Result};

const WINDOW_SIZE: usize = 4;
const RESEND_DELAY_MS: u64 = 1500;

bitflags! {
    #[derive(Default)]
    struct MspFlags: u8 {
        const MSP_SHUTDOWN = 0b0000_0001;
        const MSP_ACK = 0b0000_0010;
        const MSP_CONNECT = 0b0000_0100;
        const MSP_STOP = 0b0000_1000;
    }
}

enum ConnectionState {
    Waiting(MdpSocket),
    Error(Error),
    Connected
}

fn decode_header(buf: &[u8]) -> IResult<&[u8], (MspFlags, u16, u16)> {
    let (r, flags) = try_parse!(buf, be_u8);
    let flags = MspFlags::from_bits(flags).unwrap_or_else(|| Default::default());
    let (r, ack_seq) = if flags.contains(MspFlags::MSP_ACK) {
        try_parse!(r, be_u16)
    } else {
        (r, 0)
    };
    let (r, seq) = try_parse!(r, be_u16);
    IResult::Done(r, (flags, ack_seq, seq))
}

fn decode_message(buf: &[u8]) -> Result<(MspFlags, u16, u16, &[u8])> {
    match decode_header(buf) {
        IResult::Done(r, (flags, ack_seq, seq)) => Ok((flags, ack_seq, seq, r)),
        IResult::Incomplete(needed) => Err(Error::ParseIncomplete(needed)),
        IResult::Error(error) => Err(Error::ParseError(error)),
    }
}

fn encode_message<B: BufMut>(flags: u8, ack_seq: u16, seq: u16, item: &[u8], buf: &mut B) {
    let f = MspFlags::from_bits(flags).unwrap_or_else(|| Default::default());
    buf.put_u8(flags);
    if f.contains(MspFlags::MSP_ACK) {
        buf.put_u16::<BigEndian>(ack_seq);
    }
    buf.put_u16::<BigEndian>(seq);
    buf.put_slice(item.as_ref());
}

struct MspMessage {
    seq: u16,
    contents: Vec<u8>,
    queued_at: Instant
}

impl PartialEq for MspMessage {
    fn eq(&self, other: &MspMessage) -> bool {
        self.seq.eq(&other.seq)
    }
}

impl Eq for MspMessage {}

impl PartialOrd for MspMessage {
    fn partial_cmp(&self, other: &MspMessage) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MspMessage {
    fn cmp(&self, other: &MspMessage) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}

/// A virtual MSP socket
///
/// This represents a potential MDP-over-MSP connection. Typically, an `MDP` socket is converted
/// into an `MSP` socket via the `From` trait, and then a method is called to either listen on a
/// particular `MDP` port for an incoming connection or to connect to a remote address.
pub struct Socket {
    inner: MdpSocket,
}

impl From<MdpSocket> for Socket {
    fn from(s: MdpSocket) -> Self {
        Socket { inner: s }
    }
}

impl Socket {
    /// Connect to a remote address
    ///
    /// This takes a remote `MDP` socket address and yields a `Connection` object, which is a
    /// `Future` representing the connection in progress.
    pub fn connect<A: Into<SocketAddr>>(mut self, dst: A) -> Connection {
        let dst = dst.into();
        debug!("Connecting to {:?}.", dst);
        let mut flags: MspFlags = Default::default();
        flags.insert(MspFlags::MSP_CONNECT);
        let mut buf = vec![];
        buf.put_u8(flags.bits());
        buf.put_u16::<BigEndian>(1);
        let sent = self.inner.start_send((buf, dst, State::Encrypted));
        let state = match sent {
            Ok(AsyncSink::Ready) => ConnectionState::Waiting(self.inner),
            _ => ConnectionState::Error(Error::MspConnectError)
        };
        Connection {
            inner: state,
            dst: dst,
            listening: false,
        }
    }

    /// Listen on a local port.
    ///
    /// This listens for incoming connection attempts on the socket's address and port, and yields
    /// a `Connection` object, which is a `Future` representing the pending connection.
    pub fn listen(self) -> Connection {
        debug!("Listening.");
        Connection {
            inner: ConnectionState::Waiting(self.inner),
            dst: (ADDR_EMPTY, 0).into(),
            listening: true,
        }
    }

    /// Close an existing MSP socket.
    ///
    /// This closes an existing `MSP` socket to further connections.
    pub fn close(&mut self) {
        let _ = self.inner.close();
    }
}

/// A pending MSP connection.
///
/// This is a `Future` that represents a pending `MSP` connection, either incoming or outgoing.
/// When this `Future` completes, it yields a `Transport`, representing the open, bi-directional
/// message stream.
pub struct Connection {
    inner: ConnectionState,
    dst: SocketAddr,
    listening: bool,
}

impl Future for Connection {
    type Item = Transport;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match mem::replace(&mut self.inner, ConnectionState::Connected) {
            ConnectionState::Waiting(mut socket) => {
                match try_ready!(socket.poll()) {
                    Some((ref msg, dst, ref state)) => {
                        if let Ok((flags, ack_seq, seq, remaining)) = decode_message(msg) {
                            if flags.contains(MspFlags::MSP_ACK) && ack_seq == 1
                                && state == &State::Encrypted && !self.listening && dst == self.dst
                            {
                                let mut stream = Transport {
                                    inner: socket,
                                    dst: dst,
                                    incoming: Vec::with_capacity(WINDOW_SIZE),
                                    outgoing: Vec::with_capacity(WINDOW_SIZE),
                                    next_incoming_seq: seq + 1,
                                    next_outgoing_seq: ack_seq + 1,
                                };
                                if !remaining.is_empty() {
                                    stream.incoming.push(MspMessage {
                                        seq: seq,
                                        contents: remaining.to_vec(),
                                        queued_at: Instant::now()
                                    });
                                }
                                debug!("Successfully connected to {:?}.", dst);
                                Ok(Async::Ready(stream))
                            } else if flags.contains(MspFlags::MSP_CONNECT)
                                && state == &State::Encrypted && self.listening
                            {
                                let mut stream = Transport {
                                    inner: socket,
                                    dst: dst,
                                    incoming: Vec::with_capacity(WINDOW_SIZE),
                                    outgoing: Vec::with_capacity(WINDOW_SIZE),
                                    next_incoming_seq: seq + 1,
                                    next_outgoing_seq: ack_seq + 1,
                                };
                                if !remaining.is_empty() {
                                    stream.incoming.push(MspMessage {
                                        seq: seq,
                                        contents: remaining.to_vec(),
                                        queued_at: Instant::now()
                                    });
                                }
                                debug!("Received connection from {:?}.", dst);
                                Ok(Async::Ready(stream))
                            } else {
                                Ok(Async::NotReady)
                            }
                        } else {
                            Err(Error::MspConnectError)
                        }
                    },
                    None => Err(Error::MspConnectError)
                }
            },
            _ => panic!()
        }
    }
}

/// An open MSP connection.
///
/// This is an open, bi-directional message stream between two `MSP` hosts. It implements both the
/// `Futures::Stream` and `Futures::Sink` traits, so it can be used as a bidirectional asynchronous
/// transport using the `Futures` library.
pub struct Transport {
    inner: MdpSocket,
    dst: SocketAddr,
    incoming: Vec<MspMessage>,
    outgoing: Vec<MspMessage>,
    next_incoming_seq: u16,
    next_outgoing_seq: u16,
}

impl Stream for Transport {
    type Item = Vec<u8>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.incoming.is_empty() {
            self.incoming.sort_unstable();
            if let Some(msg) = self.incoming.pop() {
                if msg.seq == self.next_incoming_seq {
                    self.next_incoming_seq += 1;
                    return Ok(Async::Ready(Some(msg.contents)));
                }
            }
        }
        while let Some((msg, dst, state)) = try_ready!(self.inner.poll()) {
            if dst != self.dst || state != State::Encrypted {
                continue;
            }
            if let Ok((flags, ack_seq, seq, remaining)) = decode_message(&msg) {
                if flags.contains(MspFlags::MSP_ACK) {
                    self.outgoing.retain(|m| m.seq != ack_seq);
                }
                if seq == self.next_incoming_seq {
                    self.next_incoming_seq += 1;
                    return Ok(Async::Ready(Some(remaining.to_vec())));
                } else {
                    self.incoming.push(MspMessage {
                        seq: seq,
                        contents: remaining.to_vec(),
                        queued_at: Instant::now()
                    });
                }
            }
        }
        Ok(Async::NotReady)
    }
}

impl Sink for Transport {
    type SinkItem = (Vec<u8>, SocketAddr, State);
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        for msg in &self.outgoing {
            if msg.queued_at + Duration::from_millis(RESEND_DELAY_MS) <= Instant::now() {
                let _ = self.inner
                    .start_send((msg.contents.clone(), self.dst, State::Encrypted))?;
            }
        }
        let mut buf = vec![];
        let flags = MspFlags::from_bits(0).unwrap_or_else(|| Default::default());
        encode_message(flags.bits(), 0, self.next_outgoing_seq, item.0.as_ref(), &mut buf);
        self.outgoing.push(MspMessage {
            seq: self.next_outgoing_seq,
            contents: buf.clone(),
            queued_at: Instant::now(),
        });
        self.next_outgoing_seq += 1;
        self.inner.start_send((buf, self.dst, State::Encrypted)).map_err(|e| Error::Mdp(e))
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete().map_err(|e| Error::Mdp(e))
    }
}
