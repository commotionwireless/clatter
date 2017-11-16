use bytes::BufMut;
use nom::{be_u8, be_i8, ErrorKind, IResult};
use std::io::Write;
use std::vec::Vec;
use mdp::addr::{Addr, address_parse, ADDRBYTES};
use mdp::error::{Error, Result};
use mdp::packet::Packet;

const MAGIC_VERSION: [u8; 1] = [1];
const MAGIC_ENCAP: [u8; 1] = [1];
pub const MTU_DEFAULT: usize = 1500;


bitflags! {
    flags FrameFlags: u8 {
        const FRAME_UNICAST = 0b00000001,
        const FRAME_INTERFACE = 0b00000010,
        const FRAME_SEQUENCE = 0b00000100
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Serialized(Vec<u8>),
    Deserialized {
        src: Addr,
        iface: i8,
        seq: i8,
        unicast: bool,
        packets: Vec<Packet>
    }
}



impl Frame {
    pub fn new<A: Into<Addr>>(src: A, iface: i8, seq: i8, unicast: bool) -> Frame {
        let src_addr: Addr = src.into();
        Frame::Deserialized {
            src: src_addr,
            iface: iface,
            seq: seq,
            unicast: unicast,
            packets: Vec::new()
        }
    }

    pub fn from_packets<A: Into<Addr>>(packets: &mut Vec<Packet>, src: A, iface: i8, seq: i8, unicast: bool) -> Frame {
        let src_addr: Addr = src.into();
        let mut p: Vec<Packet> = Vec::new();
        p.append(packets);
        Frame::Deserialized {
            src: src_addr,
            iface: iface,
            seq: seq,
            unicast: unicast,
            packets: p
        }
    }

    pub fn header_len(&self, iface: i8, seq: i8) -> usize {
        let mut length: usize = ADDRBYTES + 3;
        if iface >= 0 {
            length += 1;
        }
        if seq >= 0 {
            length += 1;
        }
        length
    }

    pub fn len(&self) -> usize {
        match *self {
            Frame::Serialized(ref bytes) => bytes.len(),
            Frame::Deserialized { src, iface, seq, ref packets, .. } => {
                packets.iter().fold(0, |all, p| all + p.len(src)) + self.header_len(iface, seq)
            }
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match *self {
            Frame::Deserialized { .. } => Err(Error::FrameNeedsSerialized),
            Frame::Serialized(ref bytes) => Ok(bytes)
        }
    }

    pub fn as_packets(&self) -> Result<&Vec<Packet>> {
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { ref packets, .. } => Ok(packets)
        }
    }

    pub fn as_mut_packets(&mut self) -> Result<&mut Vec<Packet>> {
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { ref mut packets, .. } => Ok(packets)
        }
    }

    pub fn is_unicast(&self) -> Result<bool> {
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { unicast, .. } => Ok(unicast)
        }
    }

    pub fn get_src(&self) -> Result<Addr> {
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { src, .. } => Ok(src)
        }
    }

    pub fn push(&mut self, p: Packet, mtu: usize) -> Result<()> {
        let length = self.len();
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { src, ref mut packets, .. } => {
                if p.len(src) + length < mtu {
                    packets.push(p);
                    Ok(())
                } else {
                    Err(Error::FrameFull)
                }
            }
        }
    }

    fn serialize_header<B: BufMut>(&self, buf: &mut B) -> Result<usize> {
        match *self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { src, iface, seq, .. } => {
                let mut flags = FrameFlags { bits: 0 };
                if iface >= 0 {
                    flags.insert(FRAME_INTERFACE)
                };
                if seq >= 0 {
                    flags.insert(FRAME_SEQUENCE)
                };
                let before: usize = buf.remaining_mut();
                buf.put_u8(MAGIC_VERSION[0]);
                buf.put_u8(MAGIC_ENCAP[0]);
                buf.put_slice(src.as_ref());
                buf.put_u8(flags.bits);
                if iface >= 0 {
                    buf.put_i8(iface);
                };
                if seq >= 0 {
                    buf.put_i8(seq);
                };
                Ok(before - buf.remaining_mut())
            }
        }
    }

    pub fn serialize(self, mtu: usize) -> Result<Frame> {
        match self {
            Frame::Serialized(_) => Err(Error::FrameNeedsDeserialized),
            Frame::Deserialized { src, ref packets, .. } => {
                let mut buf = vec![];
                let w = self.serialize_header(&mut buf)?;
                let pw: Result<usize> = packets.iter().map(|p| p.serialize(src, &mut buf)).sum(); 
                match pw {
                    Ok(n) if n + w <= mtu => Ok(Frame::Serialized(buf)),
                    _ => Err(Error::FrameTooLarge)
                }
            }
        }
    }

    pub fn serialize_into(self, buf: &mut Vec<u8>) -> Result<usize> {
        match self {
            Frame::Serialized(b) => buf.write(&b).map_err(|e| Error::Io(e)),
            Frame::Deserialized { src, ref packets, .. } => {
                let w = self.serialize_header(buf)?;
                let p: Result<usize> = packets.iter().map(|p| p.serialize(src, buf)).sum();
                p.map(|i| i + w)
            }
        }
    }

    named!(deserialize_version<&[u8], &[u8]>, tag!(MAGIC_VERSION));
    named!(deserialize_encap<&[u8], &[u8]>, tag!(MAGIC_ENCAP));

    fn deserialize_header<'a>(buf: &'a [u8]) -> IResult<&'a [u8], (Addr, i8, i8, bool)> {
        let (r, _) = try_parse!(&buf, Frame::deserialize_version);
        let (r, _) = try_parse!(r, Frame::deserialize_encap);
        let (r, src): (&[u8], Addr) = try_parse!(r, address_parse);
        let (r, bits) = try_parse!(r, be_u8);
        let flags = match FrameFlags::from_bits(bits) {
            Some(flags) => flags,
            None => return IResult::Error(ErrorKind::Custom(42))
        };
        let (r, iface): (&[u8], i8) = if flags.contains(FRAME_INTERFACE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        let (r, seq): (&[u8], i8) = if flags.contains(FRAME_SEQUENCE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        IResult::Done(r, (src, iface, seq, flags.contains(FRAME_UNICAST)))
    }

    named_args!(deserialize_packets(src: Addr) < Vec<Packet> >, many1!(apply!(Packet::deserialize, src)));
    
    pub fn deserialize<'a>(buf: &'a [u8], length: usize) -> Result<Frame> {
        match Frame::deserialize_header(&buf[..length]) {
            IResult::Done(r, (src, iface, seq, unicast)) => {
                match Frame::deserialize_packets(r, src) {
                    IResult::Done(_, packets) => {
                        Ok(Frame::Deserialized {
                            src: src,
                            iface: iface,
                            seq: seq,
                            unicast: unicast,
                            packets: packets
                        })
                    },
                    IResult::Incomplete(needed) => Err(Error::ParseIncomplete(needed)),
                    IResult::Error(err) => Err(Error::ParseError(err))
                }
            }
            IResult::Incomplete(needed) => Err(Error::ParseIncomplete(needed)),
            IResult::Error(err) => Err(Error::ParseError(err))
        }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use mdp::addr::*;
    use mdp::packet::*;

    #[test]
    fn deserialize_single_plain() {
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        let mut f1 = Frame::new(&s1, -1, -1, false);
        f1.push(p1, MTU_DEFAULT).unwrap();
        println!("f1: {:?}", f1);
        let f1s = f1.serialize(MTU_DEFAULT).unwrap();
        println!("f1 serialized: {:?}", f1s);
        let buf = f1s.as_bytes().unwrap();
        let mut f2 = Frame::deserialize(buf, buf.len()).unwrap();
        let p1d = f2.as_mut_packets().unwrap().pop().unwrap();
        assert!(p2.equiv(&p1d))
    }

    #[test]
    fn deserialize_single_encrypted() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let mut p1 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        let p2 = p1.clone();
        p1.encrypt(&mut s1).unwrap();
        let mut f1 = Frame::new(&s1, 1, 1, false);
        f1.push(p1, MTU_DEFAULT).unwrap();
        let f1s = f1.serialize(MTU_DEFAULT).unwrap();
        let buf = f1s.as_bytes().unwrap();
        let mut f2 = Frame::deserialize(buf, buf.len()).unwrap();
        let mut p1d = f2.as_mut_packets().unwrap().pop().unwrap();
        p1d.decrypt(&mut s2).unwrap();
        assert!(p2.equiv(&p1d))
    }

    #[test]
    fn deserialize_multiple() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let s3 = LocalAddr::new();
        let p1 = Packet::new((&s1, 1), (&s3, 1), &s2, 10, QOS_DEFAULT, false, "Packet1".as_bytes());
        let mut p2 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet2".as_bytes());
        let mut p3 = Packet::new((&s1, 1), (&s2, 1), &s2, 10, QOS_DEFAULT, false, "Packet3".as_bytes());
        let p1c = p1.clone();
        let p2c = p2.clone();
        p2.encrypt(&mut s1).unwrap();
        p3.sign(&mut s1).unwrap();
        let mut f1 = Frame::new(&s1, 1, 1, false);
        f1.push(p1, MTU_DEFAULT).unwrap();
        f1.push(p2, MTU_DEFAULT).unwrap();
        f1.push(p3, MTU_DEFAULT).unwrap();
        let f1s = f1.serialize(MTU_DEFAULT).unwrap();
        let buf = f1s.as_bytes().unwrap();
        let mut f2 = Frame::deserialize(buf, buf.len()).unwrap();
        let mut v1 = f2.as_mut_packets().unwrap();
        let p3d = v1.pop().unwrap();
        let mut p2d = v1.pop().unwrap();
        let p1d = v1.pop().unwrap();
        p2d.decrypt(&mut s2).unwrap();
        assert!(p1d == p1c && p2c == p2d && p3d.verify().is_ok())
    }

}
