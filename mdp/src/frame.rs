use std::{iter::once, mem, ops::{Deref, DerefMut}, vec::IntoIter};
use cookie_factory::GenError;
use nom::{self, IResult, be_i8, be_u8};

use addr::{address_parse, Addr};
use error::{Error, Result, GResult};
use packet::Packet;

const MAGIC_VERSION: [u8; 1] = [1];
const MAGIC_ENCAP_MULTIPLE: u8 = 0;
const MAGIC_ENCAP_SINGLE: u8 = 1;

bitflags! {
    struct FrameFlags: u8 {
        const FRAME_UNICAST = 0b0000_0001;
        const FRAME_INTERFACE = 0b0000_0010;
        const FRAME_SEQUENCE = 0b0000_0100;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    src: Addr,
    iface: i8,
    seq: i8,
    unicast: bool,
}

impl Header {
    fn new(src: &Addr, iface: i8, seq: i8, unicast: bool) -> Header {
        Header {
            src: *src,
            iface: iface,
            seq: seq,
            unicast: unicast,
        }
    }

    pub fn src(&self) -> &Addr {
        &self.src
    }

    pub fn iface(&self) -> i8 {
        self.iface
    }

    pub fn set_iface(&mut self, iface: i8) {
        self.iface = iface
    }

    pub fn seq(&self) -> i8 {
        self.seq
    }

    pub fn set_seq(&mut self, seq: i8) {
        self.seq = seq
    }

    pub fn is_unicast(&self) -> bool {
        self.unicast
    }

    pub fn set_unicast(&mut self, unicast: bool) {
        self.unicast = unicast
    }

    pub fn len(&self) -> usize {
        let mut length: usize = self.src.len() + 3;
        if self.iface >= 0 {
            length += 1;
        }
        if self.seq >= 0 {
            length += 1;
        }
        length
    }

    pub fn encode<'b>(&self, buf: (&'b mut [u8], usize)) -> GResult<(&'b mut [u8], usize)> {
        let mut flags = FrameFlags { bits: 0 };
        if self.iface >= 0 {
            flags.insert(FrameFlags::FRAME_INTERFACE)
        };
        if self.seq >= 0 {
            flags.insert(FrameFlags::FRAME_SEQUENCE)
        };
        if self.unicast {
            flags.insert(FrameFlags::FRAME_UNICAST)
        };
        do_gen!(
            buf,
            gen_slice!(self.src.as_ref()) >>
            gen_be_u8!(flags.bits) >>
            gen_cond!(self.iface >= 0, gen_be_i8!(self.iface)) >>
            gen_cond!(self.seq >= 0, gen_be_i8!(self.seq))
        )
    }
    
    fn decode_header<'a>(buf: &'a [u8]) -> IResult<&'a [u8], Header> {
        let (r, src): (&[u8], Addr) = try_parse!(buf, address_parse);
        let (r, bits) = try_parse!(r, be_u8);
        let flags = match FrameFlags::from_bits(bits) {
            Some(flags) => flags,
            None => return Err(nom::Err::Error(error_position!(buf, nom::ErrorKind::Custom(42)))),
        };
        let (r, iface): (&[u8], i8) = if flags.contains(FrameFlags::FRAME_INTERFACE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        let (r, seq): (&[u8], i8) = if flags.contains(FrameFlags::FRAME_SEQUENCE) {
            try_parse!(r, be_i8)
        } else {
            (r, -1)
        };
        Ok((
            r,
            Header::new(&src, iface, seq, flags.contains(FrameFlags::FRAME_UNICAST)),
        ))
    }

    pub fn decode(buf: &[u8]) -> Result<(&[u8], Header)> {
        match Header::decode_header(buf) {
            Ok((r, header)) => Ok((r, header)),
            Err(nom::Err::Incomplete(needed)) => Err(Error::ParseIncomplete(needed)),
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => Err(Error::ParseError(err.into_error_kind())),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Contents {
    Single(Packet),
    Multiple(Vec<Packet>),
}

impl Contents {
    fn encode_contents<'b>(&self, encap_src: &Addr, buf: (&'b mut [u8], usize)) -> GResult<(&'b mut [u8], usize)> {
        match *self {
            Contents::Single(ref packet) => packet.encode(encap_src, true, buf),
            Contents::Multiple(ref packets) => {
                let encoder = |buf: (&'b mut [u8], usize), p: &Packet| p.encode(encap_src, false, buf);
                do_gen!(
                    buf,
                    gen_many_ref!(packets.iter(), encoder)
                )
            }
        }
    }

    pub fn encode<B: AsMut<[u8]> + Deref<Target=[u8]>>(&self, encap_src: &Addr, buf: &mut B) -> Result<usize> {
        let start = buf.len();
        match self.encode_contents(encap_src, (buf.as_mut(), start)).map(|b| b.1) {
            Ok(end) => {
                trace!("Encoded frame of size {}.", end - start);
                Ok(end)
            },
            Err(err) => Err(Error::EncodeError(err))
        }
    }

    pub(crate) fn len(&self, encap_src: &Addr) -> usize {
        match *self {
            Contents::Single(ref packet) => packet.len(encap_src, true),
            Contents::Multiple(ref packets) => {
                packets.iter().map(|p| p.len(encap_src, false)).sum()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    header: Header,
    contents: Contents,
}

impl Frame {
    pub fn encap<A: Into<Addr> + Copy>(packet: Packet, src: A, iface: i8, seq: i8) -> Frame {
        Frame {
            header: Header::new(&src.into(), iface, seq, false),
            contents: Contents::Single(packet),
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    pub fn contents(&self) -> &Contents {
        &self.contents
    }

    pub fn contents_mut(&mut self) -> &mut Contents {
        &mut self.contents
    }

    named!(decode_version<&[u8], &[u8]>, tag!(MAGIC_VERSION));

    fn decode_frame(buf: &[u8]) -> IResult<&[u8], Frame> {
        let (r, _) = try_parse!(buf, Frame::decode_version);
        let (r, encap) = try_parse!(r, be_u8);
        let (r, header) = try_parse!(r, Header::decode_header);
        match encap {
            MAGIC_ENCAP_MULTIPLE => {
                trace!("Decoding frame ENCAP_MULTIPLE.");
                let (r, packets) =
                    try_parse!(r, many1!(complete!(apply!(Packet::decode, &header.src, false))));
                Ok((
                    r,
                    Frame {
                        header: header,
                        contents: Contents::Multiple(packets),
                    },
                ))
            }
            MAGIC_ENCAP_SINGLE => {
                trace!("Decoding frame ENCAP_SINGLE.");
                let (r, packet) = try_parse!(r, complete!(apply!(Packet::decode, &header.src, true)));
                Ok((
                    r,
                    Frame {
                        header: header,
                        contents: Contents::Single(packet),
                    },
                ))
            }
            _ => Err(nom::Err::Error(error_position!(buf, nom::ErrorKind::Custom(42))))
        }
    }

    pub fn decode<A: AsRef<[u8]>>(buf: A) -> Result<Frame> {
        match Frame::decode_frame(buf.as_ref()) {
            Ok((_, frame)) => Ok(frame),
            Err(nom::Err::Incomplete(needed)) => Err(Error::ParseIncomplete(needed)),
            Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => Err(Error::ParseError(err.into_error_kind())),
        }
    }

    fn encode_frame<'b>(&self, buf: (&'b mut [u8], usize)) -> GResult<(&'b mut [u8], usize)> {
        let header_encode = |b: (&'b mut [u8], usize)| self.header.encode(b);
        let contents_encode = |b: (&'b mut [u8], usize), tx: &Addr| self.contents.encode_contents(tx, b);
        let single = match self.contents {
            Contents::Single(_) => true,
            Contents::Multiple(_) => false
        };
        do_gen!(
            buf,
            gen_be_u8!(MAGIC_VERSION[0]) >>
            gen_if_else!(single, gen_be_u8!(MAGIC_ENCAP_SINGLE), gen_be_u8!(MAGIC_ENCAP_MULTIPLE)) >>
            gen_call!(header_encode) >>
            gen_call!(contents_encode, &self.header.src)
        )
    }

    pub fn encode<B: AsMut<[u8]> + DerefMut<Target=[u8]>>(&self, buf: &mut B) -> Result<usize> {
        match self.encode_frame((buf, 0)).map(|b| b.1) {
            Ok(end) => {
                trace!("Encoded frame of size {}.", end);
                Ok(end)
            },
            Err(err) => Err(Error::EncodeError(err))
        }
    }

    pub fn len(&self) -> usize {
        self.header.len() + self.contents.len(&self.header.src)
    }
}

impl IntoIterator for Frame {
    type Item = Packet;
    type IntoIter = IntoIter<Packet>;

    fn into_iter(self) -> Self::IntoIter {
        match self.contents {
            Contents::Multiple(v) => v.into_iter(),
            Contents::Single(p) => vec![p].into_iter(),
        }
    }
}

impl Extend<Packet> for Frame {
    fn extend<T: IntoIterator<Item = Packet>>(&mut self, iter: T) {
        match self.contents {
            Contents::Multiple(ref mut v) => {
                v.extend(iter);
            }
            Contents::Single(_) => {
                if let Contents::Single(packet) =
                    mem::replace(&mut self.contents, Contents::Multiple(Vec::new()))
                {
                    self.extend(once(packet));
                    self.extend(iter);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use addr::*;
    use packet::*;

    #[test]
    fn decode_single_plain() {
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let p1 = Packet::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Packet1"[..]),
        );
        let mut buf = vec![0; 250];
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        let f1 = Frame::encap(p1, &s1, 0, 0);
        println!("f1: {:?}", f1);
        let wr = f1.encode(&mut buf).unwrap();
        println!("f1 encoded: {:?}", buf);
        let f2 = Frame::decode(&buf[..wr]).unwrap();
        println!("f1 decoded: {:?}", f2);
        let p1d = f2.into_iter().next().unwrap();
        println!("p1d: {:?}", p1d);
        assert!(p2.equiv(&p1d))
    }

    #[test]
    fn decode_single_encrypted() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let mut p1 = Packet::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Packet1"[..]),
        );
        let mut buf = vec![0; 250];
        let p2 = p1.clone();
        p1.encrypt(&mut s1).unwrap();
        let f1 = Frame::encap(p1, &s1, 0, 0);
        let wr = f1.encode(&mut buf).unwrap();
        let f2 = Frame::decode(&buf[..wr]).unwrap();
        let mut p1d = f2.into_iter().next().unwrap();
        p1d.decrypt(&mut s2).unwrap();
        assert!(p2.equiv(&p1d))
    }

    #[test]
    fn decode_multiple() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let s3 = LocalAddr::new();
        let p1 = Packet::new(
            (&s1, 1),
            (&s3, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Packet1"[..]),
        );
        let mut p2 = Packet::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Packet2"[..]),
        );
        let mut p3 = Packet::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Packet3"[..]),
        );
        let mut buf = vec![0; 1500];
        let p1c = p1.clone();
        let p2c = p2.clone();
        p2.encrypt(&mut s1).unwrap();
        p3.sign(&mut s1).unwrap();
        println!("p1: {:?}", p1);
        println!("p2: {:?}", p2);
        println!("p3: {:?}", p3);
        let mut f1 = Frame::encap(p1, &s1, 0, 0);
        let f2 = Frame::encap(p2, &s1, 0, 0);
        let f3 = Frame::encap(p3, &s1, 0, 0);
        f1.extend(f2);
        f1.extend(f3);
        println!("f1: {:?}", f1);
        let _f1s = f1.encode(&mut buf).unwrap();
        println!("f1 encoded: {:?}", buf);
        let f2 = Frame::decode(&buf).unwrap();
        println!("f1 decoded: {:?}", buf);
        let mut v1 = f2.into_iter();
        let p1d = v1.next().unwrap();
        let mut p2d = v1.next().unwrap();
        let p3d = v1.next().unwrap();
        p2d.decrypt(&mut s2).unwrap();
        println!("p1 decoded: {:?}", p1d);
        println!("p2 decoded: {:?}", p2d);
        println!("p3 decoded: {:?}", p3d);
        assert!(p1d.equiv(&p1c) && p2c.equiv(&p2d) && p3d.verify().is_ok())
    }

}
