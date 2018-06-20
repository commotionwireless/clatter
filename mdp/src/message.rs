use std::u16;
use bytes::BytesMut;
use cookie_factory::GenError;
use nom::{self, IResult, be_i8, be_u16, be_u8};
use addr::{address_parse, Addr, LocalAddr, SocketAddr, ADDR_BROADCAST, ADDR_EMPTY, NONCEBYTES,
           SIGNATUREBYTES};
use error::{Result, GResult};
use qos;
use broadcast::{self, bid_parse, BIDBYTES, BID_EMPTY};
use payload::Payload;

pub const TTL_MAX: u8 = 31;
pub const QOS_DEFAULT: qos::Class = qos::Class::Ordinary;

bitflags! {
    struct MessageFlags: u8 {
        const PACKET_SENDER_SAME = 0b0000_0001;
        const PACKET_BROADCAST = 0b0000_0010;
        const PACKET_ONE_HOP = 0b0000_0100;
        const PACKET_ENCRYPTED = 0b0000_1000;
        const PACKET_SIGNED = 0b0001_0000;
        const PACKET_ACK_SOON = 0b0010_0000;
    }
}

named!(ttl_qos_parse<(u8, qos::Class)>, 
    do_parse!(
        ttl_qos: bits!(pair!(take_bits!(u8, 5), take_bits!(u8, 3))) >>
        qos: switch!(value!(ttl_qos.1),
            0 => value!(qos::Class::Voice) |
            1 => value!(qos::Class::Management) |
            2 => value!(qos::Class::Video) |
            3 => value!(qos::Class::Ordinary) |
            4 => value!(qos::Class::Opportunistic)
        ) >>
        (ttl_qos.0, qos)
    )
);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    Encrypted,
    Signed,
    Plain,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    src: Addr,
    dst: Addr,
    bid: broadcast::Id,
    pub(crate) rx: Addr,
    ttl: u8,
    pub(crate) qos: qos::Class,
    seq: i8,
    ack_soon: bool,
    local: bool,
    payload: Payload,
}

impl Message {
    pub fn new<A: Into<SocketAddr>, B: Into<Addr>>(
        src: A,
        dst: A,
        rx: B,
        ttl: u8,
        qos: qos::Class,
        seq: i8,
        ack_soon: bool,
        contents: &mut BytesMut,
    ) -> Message {
        let s = src.into();
        let d = dst.into();
        let b = if d.addr == ADDR_BROADCAST {
            broadcast::Id::new()
        } else {
            BID_EMPTY
        };
        let t = match ttl {
            n if n == 0 => 1,
            n if n > TTL_MAX => TTL_MAX,
            _ => ttl,
        };
        Message {
            src: s.addr,
            dst: d.addr,
            bid: b,
            rx: rx.into(),
            ttl: t,
            qos: qos,
            seq: seq,
            ack_soon: ack_soon,
            local: true,
            payload: Payload::Plain {
                src_port: s.port,
                dst_port: d.port,
                data: contents.take(),
            },
        }
    }

//    named_args!(pub decode(tx: Addr, single: bool)<Message>,
//        do_parse!(
//            bits: be_u8 >>
//            flags: expr_opt!(MessageFlags::from_bits(bits)) >>
//            src: alt_complete!(cond_reduce!(!flags.contains(MessageFlags::PACKET_SENDER_SAME), return_error!(call!(address_parse))) | tx.into()) >>
//            dst: alt_complete!(cond_reduce!(!flags.contains(MessageFlags::PACKET_BROADCAST), return_error!(call!(address_parse))) | value!(ADDR_BROADCAST)) >>
//            rx: alt_complete!(cond_reduce!(!(flags.contains(MessageFlags::PACKET_BROADCAST) || flags.contains(MessageFlags::PACKET_ONE_HOP)), return_error!(call!(address_parse))) | value!(ADDR_EMPTY)) >>
//            bid: alt_complete!(cond_reduce!(flags.contains(MessageFlags::PACKET_BROADCAST) && !flags.contains(MessageFlags::PACKET_ONE_HOP), return_error!(call!(bid_parse))) | value!(BID_EMPTY)) >>
//            qos_ttl: alt_complete!(cond_reduce!(!flags.contains(MessageFlags::PACKET_ONE_HOP), return_error!(call!(ttl_qos_parse))) | value!((0, QOS_DEFAULT))) >>
//            seq: be_i8 >>
//            ack_soon: flags.contains(MessageFlags::PACKET_ACK_SOON) >>
//            payload: switch!(expr_res!(flags.state()),
//                        State::Encrypted => do_parse!(
//                                                len: alt_complete!(cond_reduce!(single, 
//
//

    pub fn decode<A: Into<Addr>>(buf: &[u8], tx: A, single: bool) -> IResult<&[u8], Message> {
        let (r, bits) = try_parse!(buf, be_u8);
        if let Some(x) = MessageFlags::from_bits(bits) {
            let flags = x;
            let (r, src) = if !flags.contains(MessageFlags::PACKET_SENDER_SAME) {
                try_parse!(r, address_parse)
            } else {
                (r, tx.into())
            };
            let (r, dst, bid, rx, ttl, qos) = if !flags.contains(MessageFlags::PACKET_BROADCAST) {
                let (r, dst) = try_parse!(r, address_parse);
                let (r, rx, ttl, qos) = if !flags.contains(MessageFlags::PACKET_ONE_HOP) {
                    let (r, rx) = try_parse!(r, address_parse);
                    let (r, (ttl, qos)) = try_parse!(r, ttl_qos_parse);
                    (r, rx, ttl, qos)
                } else {
                    (r, ADDR_EMPTY, 0, QOS_DEFAULT)
                };
                (r, dst, BID_EMPTY, rx, ttl, qos)
            } else {
                let (r, bid, ttl, qos) = if !flags.contains(MessageFlags::PACKET_ONE_HOP) {
                    let (r, bid) = try_parse!(r, bid_parse);
                    let (r, (ttl, qos)) = try_parse!(r, ttl_qos_parse);
                    (r, bid, ttl, qos)
                } else {
                    (r, BID_EMPTY, 0, QOS_DEFAULT)
                };
                (r, ADDR_BROADCAST, bid, ADDR_EMPTY, ttl, qos)
            };
            let (r, seq) = try_parse!(r, be_i8);
            if flags.contains(MessageFlags::PACKET_ENCRYPTED) {
                let (r, len) = if single {
                    let len = r.len() - 1 - NONCEBYTES;
                    (r, len as u16)
                } else {
                    try_parse!(r, be_u16)
                };
                Payload::decode_encrypted(r, len).map(|(r, (algo, nonce, data))|
                    (
                        r,
                        Message {
                            src: src,
                            dst: dst,
                            bid: bid,
                            rx: rx,
                            ttl: ttl,
                            qos: qos,
                            seq: seq,
                            ack_soon: flags.contains(MessageFlags::PACKET_ACK_SOON),
                            local: false,
                            payload: Payload::Encrypted {
                                algo: algo,
                                nonce: nonce,
                                data: data,
                            }
                        }
                    )
                )
            } else if flags.contains(MessageFlags::PACKET_SIGNED) {
                let (r, len) = if single {
                    let len = r.len() - 5 - SIGNATUREBYTES;
                    (r, len as u16)
                } else {
                    try_parse!(r, be_u16)
                };
                Payload::decode_signed(r, len).map(|(r, (algo, src_port, dst_port, sig, data))| 
                    (
                        r,
                        Message {
                            src: src,
                            dst: dst,
                            bid: bid,
                            rx: rx,
                            ttl: ttl,
                            qos: qos,
                            seq: seq,
                            ack_soon: flags.contains(MessageFlags::PACKET_ACK_SOON),
                            local: false,
                            payload: Payload::Signed {
                                algo: algo,
                                src_port: src_port,
                                dst_port: dst_port,
                                sig: sig,
                                data: data.into(),
                            }
                        }
                    )
                )
            } else {
                let (r, len) = if single {
                    let len = r.len() - 4;
                    (r, len as u16)
                } else {
                    try_parse!(r, be_u16)
                };
                Payload::decode_plain(r, len).map(|(r, (src_port, dst_port, data))| 
                    (
                        r,
                        Message {
                            src: src,
                            dst: dst,
                            bid: bid,
                            rx: rx,
                            ttl: ttl,
                            qos: qos,
                            seq: seq,
                            ack_soon: flags.contains(MessageFlags::PACKET_ACK_SOON),
                            local: false,
                            payload: Payload::Plain {
                                src_port: src_port,
                                dst_port: dst_port,
                                data: data,
                            }
                        }
                    )
                )
            }
        } else {
            Err(nom::Err::Error(error_position!(buf, nom::ErrorKind::Custom(42))))
        }
    }

    pub fn encode<'b>(&self, tx: &Addr, single: bool, buf: (&'b mut [u8], usize)) -> GResult<(&'b mut [u8], usize)> {
        let mut flags = MessageFlags { bits: 0 };
        if self.src == tx.into() {
            flags.insert(MessageFlags::PACKET_SENDER_SAME)
        };
        if self.dst == ADDR_BROADCAST {
            flags.insert(MessageFlags::PACKET_BROADCAST)
        };
        match self.payload {
            Payload::Encrypted { .. } => flags.insert(MessageFlags::PACKET_ENCRYPTED),
            Payload::Signed { .. } => flags.insert(MessageFlags::PACKET_SIGNED),
            Payload::Plain { .. } => (),
        };
        match self.ttl {
            0 => return Err(GenError::CustomError(0)),
            1 => flags.insert(MessageFlags::PACKET_ONE_HOP),
            2...TTL_MAX => (),
            _ => return Err(GenError::CustomError(0)),
        };
        let encoder = |buf: (&'b mut [u8], usize), payload: &Payload| Payload::encode(payload, buf);
        do_gen!(
            buf,
            gen_be_u8!(flags.bits) >>
            gen_cond!(!flags.contains(MessageFlags::PACKET_SENDER_SAME), gen_slice!(self.src.as_ref())) >>
            gen_if_else!(!flags.contains(MessageFlags::PACKET_BROADCAST), gen_slice!(self.dst.as_ref()), gen_cond!(!flags.contains(MessageFlags::PACKET_ONE_HOP), gen_slice!(self.bid.as_ref()))) >>
            gen_cond!(!(flags.contains(MessageFlags::PACKET_BROADCAST) || flags.contains(MessageFlags::PACKET_ONE_HOP)), gen_slice!(self.rx.as_ref())) >>
            gen_cond!(!flags.contains(MessageFlags::PACKET_ONE_HOP), gen_be_u8!(self.ttl << 3 | (self.qos as u8 & 0b0000_0111))) >>
            gen_be_i8!(self.seq) >>
            gen_cond!(!single, gen_be_u16!(self.payload.data_len() as u16)) >>
            gen_call!(encoder, &self.payload)
        )
    }

    pub fn encrypt(&mut self, s: &LocalAddr) -> Result<()> {
        self.payload = self.payload.encrypt(self.dst, s)?;
        Ok(())
    }

    pub fn decrypt(&mut self, s: &LocalAddr) -> Result<()> {
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

    pub fn equiv(&self, other: &Message) -> bool {
        self.src == other.src && self.dst == other.dst && self.bid == other.bid
            && self.rx == other.rx && self.qos == other.qos && self.payload == other.payload
    }

    pub fn len<A: Into<Addr>>(&self, tx: A, single: bool) -> usize {
        let mut size: usize = 1 + self.payload.len(); //There's always a payload and flags.
        if self.src != tx.into() {
            size += self.src.len(); //Source address.
        }

        size += 1; //Sequence number

        if !(self.ttl == 1) {
            size += 1; //TTL and QoS fields.
            if self.src == ADDR_BROADCAST {
                size += BIDBYTES;
            }
        }

        if self.dst != ADDR_BROADCAST {
            size += self.dst.len(); //Destination address.
        }

        if !(self.src == ADDR_BROADCAST || self.ttl == 1) {
            size += self.rx.len(); //Receive address.
        }

        if !single {
            size += 2; //Specify length, unless it's the only message in the frame.
        }

        size
    }

    pub fn src(&self) -> &Addr {
        &self.src
    }

    pub fn set_src(&mut self, addr: &Addr) {
        self.src = *addr
    }

    pub fn dst(&self) -> &Addr {
        &self.dst
    }

    pub fn src_port(&self) -> Option<u32> {
        match self.payload {
            Payload::Plain { src_port, .. } | Payload::Signed { src_port, .. } => Some(src_port),
            Payload::Encrypted { .. } => None,
        }
    }

    pub fn dst_port(&self) -> Option<u32> {
        match self.payload {
            Payload::Plain { dst_port, .. } | Payload::Signed { dst_port, .. } => Some(dst_port),
            Payload::Encrypted { .. } => None,
        }
    }

    pub fn rx(&self) -> &Addr {
        &self.rx
    }

    pub fn set_rx(&mut self, addr: &Addr) {
        self.rx = *addr
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        if ttl < TTL_MAX {
            self.ttl = ttl
        } else {
            self.ttl = TTL_MAX
        }
    }

    pub fn ttl_decrement(&mut self) {
        if self.ttl != 0 {
            self.ttl -= 1
        } else {
            self.ttl = 0
        }
    }

    pub fn bid(&self) -> &broadcast::Id {
        &self.bid
    }

    pub fn seq(&self) -> i8 {
        self.seq
    }

    pub fn is_local(&self) -> bool {
        self.local
    }

    pub fn state(&self) -> State {
        match self.payload {
            Payload::Plain { .. } => State::Plain,
            Payload::Signed { .. } => State::Signed,
            Payload::Encrypted { .. } => State::Encrypted,
        }
    }

    pub fn contents(&self) -> Result<&BytesMut> {
        self.payload.contents()
    }

    pub fn contents_mut(&mut self) -> Result<&mut BytesMut> {
        self.payload.contents_mut()
    }

    pub fn take(&mut self) -> Result<BytesMut> {
        self.payload.take()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use addr::*;

    #[test]
    fn encrypt_decrypt() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let mut p1 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
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
        let mut p1 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        p1.sign(&mut s1).unwrap();
        assert!(p1.verify().is_ok())
    }

    #[test]
    fn decode_plain() {
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let a1: Addr = s1.clone().into();
        let mut buf = vec![0; 250];
        let p1 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        let (buf, wr) = p1.encode(&a1, false, (&mut buf, 0)).unwrap();
        println!("p1 encoded: {:?}", buf);
        println!("p1 size: {:?}", wr);
        let (_, p1d) = Message::decode(&buf[..wr], &a1, false).unwrap();
        println!("p1 decoded: {:?}", p1d);
        assert!(p1d.equiv(&p2))
    }

    #[test]
    fn decode_broadcast() {
        let s1 = LocalAddr::new();
        let a1 = Addr::from(&s1);
        let mut buf = vec![0; 250];
        let p1 = Message::new(
            (&a1, 1),
            (&ADDR_BROADCAST, 1),
            ADDR_EMPTY,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        let (buf, wr) = p1.encode(&a1, false, (&mut buf, 0)).unwrap();
        println!("p1 encoded: {:?}", buf);
        println!("p1 size: {:?}", wr);
        let (_, p1d) = Message::decode(&buf[..wr], &a1, false).unwrap();
        println!("p1 decoded: {:?}", p1d);
        assert!(p1d.equiv(&p2))
    }

    #[test]
    fn decode_encrypted() {
        let mut s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let a1: Addr = s1.clone().into();
        let mut buf = vec![0; 250];
        let mut p1 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        println!("p1: {:?}", p1);
        let p2 = p1.clone();
        p1.encrypt(&mut s1).unwrap();
        let (buf, wr) = p1.encode(&a1, true, (&mut buf, 0)).unwrap();
        println!("p1 encoded: {:?}", buf);
        let (_, mut p1d) = Message::decode(&buf[..wr], &a1, true).unwrap();
        p1d.decrypt(&mut s2).unwrap();
        println!("p1 decoded: {:?}", p1);
        assert!(p1d.equiv(&p2))
    }

    #[test]
    fn decode_signed() {
        let mut s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let a1: Addr = s1.clone().into();
        let mut buf = vec![0; 250];
        let mut p1 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        println!("p1: {:?}", p1);
        p1.sign(&mut s1).unwrap();
        let (buf, wr) = p1.encode(&a1, true, (&mut buf, 0)).unwrap();
        println!("p1 encoded: {:?}", buf);
        let (_, p1d) = Message::decode(&buf[..wr], &a1, true).unwrap();
        assert!(p1d.verify().is_ok())
    }
}
