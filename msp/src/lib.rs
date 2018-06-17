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
extern crate cookie_factory;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate mdp;
#[macro_use]
extern crate nom;

mod error;

use std::{
    cmp::Ordering,
    default::Default,
    mem,
    time::{Duration, Instant},
    vec::Vec
};

use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{prelude::*, Sink, Stream};
use nom::{be_u16, be_u8, rest};

use mdp::{
    addr::{ADDR_EMPTY, SocketAddr},
    socket::{Decoder, Encoder, Framed, Socket as MdpSocket, State}
};

use error::{Error, GResult, Result};

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
    Waiting(Framed<MspCodec>),
    Error(Error),
    Connected
}

struct MspCodec;

impl Default for MspCodec {
    fn default() -> MspCodec { MspCodec }
} 

impl Decoder for MspCodec {
    type Item = (MspFlags, u16, u16, BytesMut);
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        //try_parse!(buf.as_ref(), decode_message)
        decode_message(buf).map(|res| Some(res.1)).map_err(|err| Error::ParseError(err.into_error_kind()))
    }
}

impl Encoder for MspCodec {
    type Item = (MspFlags, u16, u16, BytesMut);
    type Error = Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<()> {
        encode_message((buf.as_mut(), 0), item.0, item.1, item.2, &item.3).map(|_| ()).map_err(|err| Error::EncodeError(err))
    }
}

named!(decode_message<(MspFlags, u16, u16, BytesMut)>,
    do_parse!(
        bits: be_u8 >>
        flags: expr_opt!(MspFlags::from_bits(bits)) >>
        ack_seq: alt_complete!(cond_reduce!(flags.contains(MspFlags::MSP_ACK), be_u16) | value!(0)) >>
        seq: be_u16 >>
        remaining: rest >>
        (flags, ack_seq, seq, BytesMut::from(remaining))
    )
);

fn encode_message<'b>(buf: (&'b mut [u8], usize), flags: MspFlags, ack_seq: u16, seq: u16, contents: &BytesMut) -> GResult<(&'b mut [u8], usize)> {
    do_gen!(
        buf,
        gen_be_u8!(flags.bits()) >>
        gen_cond!(flags.contains(MspFlags::MSP_ACK), gen_be_u16!(ack_seq)) >>
        gen_be_u16!(seq) >>
        gen_slice!(contents)
    )
}

struct MspMessage {
    flags: MspFlags,
    ack_seq: u16,
    seq: u16,
    contents: BytesMut,
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
    inner: Framed<MspCodec>,
}

impl From<MdpSocket> for Socket {
    fn from(s: MdpSocket) -> Self {
        Socket { inner: Framed::new(s, MspCodec::default()) }
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
        let sent = self.inner.start_send(((flags, 1, 1, BytesMut::new()), dst, State::Encrypted));
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
                    Some(((flags, ack_seq, seq, remaining), dst, state)) => {
                        if flags.contains(MspFlags::MSP_ACK) && ack_seq == 1
                            && state == State::Encrypted && !self.listening && dst == self.dst
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
                                    flags: flags,
                                    ack_seq: ack_seq,
                                    seq: seq,
                                    contents: remaining,
                                    queued_at: Instant::now()
                                });
                            }
                            debug!("Successfully connected to {:?}.", dst);
                            Ok(Async::Ready(stream))
                        } else if flags.contains(MspFlags::MSP_CONNECT)
                            && state == State::Encrypted && self.listening
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
                                    flags: flags,
                                    ack_seq: ack_seq,
                                    seq: seq,
                                    contents: remaining,
                                    queued_at: Instant::now()
                                });
                            }
                            debug!("Received connection from {:?}.", dst);
                            Ok(Async::Ready(stream))
                        } else {
                            Ok(Async::NotReady)
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
    inner: Framed<MspCodec>,
    dst: SocketAddr,
    incoming: Vec<MspMessage>,
    outgoing: Vec<MspMessage>,
    next_incoming_seq: u16,
    next_outgoing_seq: u16,
}

impl Stream for Transport {
    type Item = BytesMut;
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
        while let Some(((flags, ack_seq, seq, remaining), dst, state)) = try_ready!(self.inner.poll()) {
            if dst != self.dst || state != State::Encrypted {
                continue;
            }
                if flags.contains(MspFlags::MSP_ACK) {
                    self.outgoing.retain(|m| m.seq != ack_seq);
                }
                if seq == self.next_incoming_seq {
                    self.next_incoming_seq += 1;
                    return Ok(Async::Ready(Some(remaining)));
                } else {
                    self.incoming.push(MspMessage {
                        flags: flags,
                        ack_seq: ack_seq,
                        seq: seq,
                        contents: remaining,
                        queued_at: Instant::now()
                    });
                }
        }
        Ok(Async::NotReady)
    }
}

impl Sink for Transport {
    type SinkItem = BytesMut;
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        for msg in &self.outgoing {
            if msg.queued_at + Duration::from_millis(RESEND_DELAY_MS) <= Instant::now() {
                let _ = self.inner
                    .start_send(((msg.flags, msg.ack_seq, msg.seq, msg.contents.clone()), self.dst, State::Encrypted))?;
            }
        }
        let flags = MspFlags::from_bits(0).unwrap_or_else(|| Default::default());
        self.outgoing.push(MspMessage {
            flags: flags,
            ack_seq: 0,
            seq: self.next_outgoing_seq,
            contents: item.clone(),
            queued_at: Instant::now(),
        });
        self.next_outgoing_seq += 1;
        match self.inner.start_send(((flags, 0, self.next_outgoing_seq - 1, item), self.dst, State::Encrypted))? {
            AsyncSink::Ready => Ok(AsyncSink::Ready),
            AsyncSink::NotReady(((_, _, _, contents), _, _)) => Ok(AsyncSink::NotReady(contents))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete()
    }
}
