use bytes::{BufMut, BigEndian};
use nom::{be_u8, be_u16, ErrorKind, IResult};
use std::u16;
use mdp::addr::{Addr, SocketAddr, address_parse, ADDR_EMPTY, ADDR_BROADCAST, ADDRBYTES, LocalAddr};
use mdp::qos;
use mdp::error::{Error, Result};
use mdp::bid::{Bid, bid_parse, BID_EMPTY, BIDBYTES};
use mdp::payload::Payload;

pub const TTL_MAX: u8 = 31;
pub const QOS_DEFAULT: qos::Class = qos::Class::Ordinary;
pub const MIN_PACKETBYTES: usize = 11;

bitflags! {
    flags PacketFlags: u8 {
        const PACKET_SENDER_SAME = 0b00000001,
        const PACKET_BROADCAST = 0b00000010,
        const PACKET_ONE_HOP = 0b00000100,
        const PACKET_ENCRYPTED = 0b00001000,
        const PACKET_SIGNED = 0b00010000,
        const PACKET_ACK_SOON = 0b00100000
    }
}

fn ttl_qos_parse(i: &[u8]) -> IResult<&[u8], (u8, qos::Class)> {
    let (r, (ttl, bytes)) = try_parse!(i, bits!(pair!(take_bits!(u8, 5), take_bits!(u8, 3))));
    match bytes {
        0 => IResult::Done(r, (ttl, qos::Class::Voice)),
        1 => IResult::Done(r, (ttl, qos::Class::Management)),
        2 => IResult::Done(r, (ttl, qos::Class::Video)),
        3 => IResult::Done(r, (ttl, qos::Class::Ordinary)),
        4 => IResult::Done(r, (ttl, qos::Class::Opportunistic)),
        _ => IResult::Error(ErrorKind::Custom(42))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    src: Addr,
    dst: Addr,
    bid: Bid,
    rx: Addr,
    ttl: u8,
    pub(crate) qos: qos::Class,
    ack_soon: bool,
    local: bool,
    payload: Payload,
}

impl Packet {
    pub fn new<A: Into<SocketAddr>, B: Into<Addr>>(src: A, dst: A, rx: B, ttl: u8, qos: qos::Class, ack_soon: bool, contents: &[u8]) -> Packet {
        let s = src.into();
        let d = dst.into();
        let b = if d.addr == ADDR_BROADCAST {
            Bid::new()
        } else {
            BID_EMPTY
        };
        let t = match ttl {
            n if n == 0 => 1,
            n if n > TTL_MAX => TTL_MAX,
            _ => ttl
        };
        Packet {
            src: s.addr,
            dst: d.addr,
            bid: b,
            rx: rx.into(),
            ttl: t,
            qos: qos,
            ack_soon: ack_soon,
            local: true,
            payload: Payload::Plain {
                src_port: s.port,
                dst_port: d.port,
                data: contents.to_vec(),
            },
        }
    }
    pub fn deserialize<'a, A: Into<Addr>>(buf: &'a [u8], frame_src: A) -> IResult<&'a [u8], Packet> {
        let (r, bits) = try_parse!(buf, be_u8);
        if let Some(x) = PacketFlags::from_bits(bits) {
            let flags = x;
            let (r, src) = if !flags.contains(PACKET_SENDER_SAME) {
                try_parse!(r, address_parse)
            } else {
                (r,frame_src.into())
            };
            let (r, dst, bid, rx, ttl, qos) = if 
                !flags.contains(PACKET_BROADCAST) {
                let (r, dst) = try_parse!(r, address_parse);
                let (r, rx, ttl, qos) = if !flags.contains(PACKET_ONE_HOP) {
                    let (r, rx) = try_parse!(r, address_parse);
                    let (r, (ttl, qos)) = try_parse!(r, ttl_qos_parse);
                    (r, rx, ttl, qos)
                } else {
                    (r, ADDR_EMPTY, 0, QOS_DEFAULT)
                };
                (r, dst, BID_EMPTY, rx, ttl, qos)
            } else {
                let (r, bid) = try_parse!(r, bid_parse);
                let (r, rx) = if !flags.contains(PACKET_ONE_HOP) {
                    try_parse!(r, address_parse)
                } else {
                    (r, ADDR_EMPTY)
                };
                (r, ADDR_EMPTY, bid, rx, 0, QOS_DEFAULT)
            };
            let (r, len) = try_parse!(r, be_u16);
            if flags.contains(PACKET_ENCRYPTED) {
                match Payload::deserialize_encrypted(r, len) {
                    IResult::Done(r, (algo, nonce, data)) => {
                        IResult::Done(r,
                                      Packet {
                                          src: src,
                                          dst: dst,
                                          bid: bid,
                                          rx: rx,
                                          ttl: ttl,
                                          qos: qos,
                                          ack_soon: flags.contains(PACKET_ACK_SOON),
                                          local: false,
                                          payload: Payload::Encrypted {
                                              algo: algo,
                                              nonce: nonce,
                                              data: data
                                          }
                                      })
                    },
                    IResult::Incomplete(needed) => IResult::Incomplete(needed),
                    IResult::Error(error) => IResult::Error(error),
                }
            } else if flags.contains(PACKET_SIGNED) {
                match Payload::deserialize_signed(r, len) {
                    IResult::Done(r, (algo, src_port, dst_port, sig, data)) => {
                        IResult::Done(r,
                                      Packet {
                                          src: src,
                                          dst: dst,
                                          bid: bid,
                                          rx: rx,
                                          ttl: ttl,
                                          qos: qos,
                                          ack_soon: flags.contains(PACKET_ACK_SOON),
                                          local: false,
                                          payload: Payload::Signed {
                                              algo: algo,
                                              src_port: src_port,
                                              dst_port: dst_port,
                                              sig: sig,
                                              data: data
                                          }
                                      })
                    },
                    IResult::Incomplete(needed) => IResult::Incomplete(needed),
                    IResult::Error(error) => IResult::Error(error),
                }
            } else {
                match Payload::deserialize_plain(r, len) {
                    IResult::Done(r, (src_port, dst_port, data)) => {
                        IResult::Done(r,
                                      Packet {
                                          src: src,
                                          dst: dst,
                                          bid: bid,
                                          rx: rx,
                                          ttl: ttl,
                                          qos: qos,
                                          ack_soon: flags.contains(PACKET_ACK_SOON),
                                          local: false,
                                          payload: Payload::Plain {
                                              src_port: src_port,
                                              dst_port: dst_port,
                                              data: data
                                          }
                                      })
                    },
                    IResult::Incomplete(needed) => IResult::Incomplete(needed),
                    IResult::Error(error) => IResult::Error(error),
                }
            }
        } else {
            IResult::Error(ErrorKind::Custom(42))
        }
    }

    pub fn serialize<A: Into<Addr>, B: BufMut>(&self, frame_src: A, buf: &mut B) -> Result<usize> {
        let mut flags = PacketFlags { bits: 0 };
        if self.src == frame_src.into() {
            flags.insert(PACKET_SENDER_SAME)
        };
        if self.dst == ADDR_BROADCAST {
            flags.insert(PACKET_BROADCAST)
        };
        match self.payload {
            Payload::Encrypted { .. } => flags.insert(PACKET_ENCRYPTED),
            Payload::Signed { .. } => {
                flags.insert(PACKET_SIGNED)
            }
            Payload::Plain { .. } => (),
        };
        match self.ttl {
            0 => return Err(Error::PacketBadTtl(0)),
            1 => flags.insert(PACKET_ONE_HOP),
            2...TTL_MAX => (()),
            n => return Err(Error::PacketBadTtl(n)),
        };
        let w = buf.remaining_mut();
        buf.put_u8(flags.bits);
        if !flags.contains(PACKET_SENDER_SAME) {
            buf.put_slice(self.src.as_ref());
        }
        if !flags.contains(PACKET_BROADCAST) {
            buf.put_slice(self.dst.as_ref());
        } else {
            if !flags.contains(PACKET_ONE_HOP) {
                buf.put_slice(self.bid.as_ref());
            }
        }
        if !(flags.contains(PACKET_BROADCAST) || flags.contains(PACKET_ONE_HOP)) {
            buf.put_slice(self.rx.as_ref());
        }
        if !flags.contains(PACKET_ONE_HOP) {
            buf.put_u8(self.ttl << 3 | (self.qos as u8 & 0b00000111));
        }
        let data_len = self.payload.data_len();
        if data_len > u16::MAX as usize { return Err(Error::PacketBadLen(data_len)); }
        buf.put_u16::<BigEndian>(data_len as u16);
        self.payload.serialize(buf)?;
        Ok(w - buf.remaining_mut())
    }

    pub fn encrypt(&mut self, s: &mut LocalAddr) -> Result<()> {
        self.payload = self.payload.encrypt(self.dst, s)?;
        Ok(())
    }

    pub fn decrypt(&mut self, s: &mut LocalAddr) -> Result<()> {
        self.payload = self.payload.decrypt(s, self.src)?;
        Ok(())
    }

    pub fn sign(&mut self, s: &LocalAddr) -> Result<()> {
        self.payload = self.payload.sign(s)?;
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.payload.verify(self.src)
    }

    pub fn equiv(&self, other: &Packet) -> bool {
        self.src == other.src && self.dst == other.dst && self.bid == other.bid &&
        self.rx == other.rx && self.qos == other.qos && self.payload == other.payload
    }

    pub fn len<A: Into<Addr>>(&self, frame_src: A) -> usize {
        let mut size: usize = 1 + self.payload.len(); //There's always a payload and flags.
        if self.src != frame_src.into() {
            size += ADDRBYTES; //Source address.
        }

        if !(self.ttl == 1) {
            size += 1; //TTL and QoS fields.
            if self.src == ADDR_BROADCAST {
                size += BIDBYTES;
            }
        }

        if self.src != ADDR_BROADCAST {
            size += ADDRBYTES; //Destination address.
        }

        if !(self.src == ADDR_BROADCAST || self.ttl == 1) {
            size += ADDRBYTES; //Receive address.
        }

        size
    }

    pub fn contents(&self) -> Result<&[u8]> {
        self.payload.contents()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdp::addr::*;

    #[test]
    fn encrypt_decrypt() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let mut p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        let p2 = p1.clone();
        p1.encrypt(&mut s1).unwrap();
        println!("p1: {:?}", p1);
        p1.decrypt(&mut s2).unwrap();
        println!("p1: {:?}", p1);
        assert_eq!(p1, p2)
    }

    #[test]
    fn sign_verify() {
        let mut s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let mut p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        p1.sign(&mut s1).unwrap();
        assert!(p1.verify().is_ok())
    }

    #[test]
    fn deserialize_plain() {
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let mut buf = vec![];
        let p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        p1.serialize(&s1, &mut buf).unwrap();
        println!("p1 serialized: {:?}", buf);
        let (_, p1d) = Packet::deserialize(&buf, &s1).unwrap();
        assert!(p1d == p2)
    }

    #[test]
    fn deserialize_encrypted() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let mut buf = vec![];
        let mut p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        p1.encrypt(&mut s1).unwrap();
        p1.serialize(&s1, &mut buf).unwrap();
        println!("p1 serialized: {:?}", buf);
        let (_, mut p1d) = Packet::deserialize(&buf, &s1).unwrap();
        p1d.decrypt(&mut s2).unwrap();
        assert!(p1d == p2)
    }

    #[test]
    fn deserialize_signed() {
        let mut s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let mut buf = vec![];
        let mut p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        println!("p1: {:?}", p1);
        p1.sign(&mut s1).unwrap();
        p1.serialize(&s1, &mut buf).unwrap();
        println!("p1 serialized: {:?}", buf);
        let (_, p1d) = Packet::deserialize(&buf, &s1).unwrap();
        assert!(p1d.verify().is_ok())
    }
}
