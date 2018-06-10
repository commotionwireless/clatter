use bytes::{BigEndian, BufMut};
use nom::{be_u32, be_u8};
use std::vec::Vec;
use std::u16;
use std::ops::Shr;
use error::{Error, Result};
use addr::{Addr, LocalAddr, Nonce, Signature, NONCEBYTES, SIGNATUREBYTES};
use util::BitMask;
use nom;

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Plain {
        src_port: u32,
        dst_port: u32,
        data: Vec<u8>,
    },
    Signed {
        algo: u8,
        src_port: u32,
        dst_port: u32,
        data: Vec<u8>,
        sig: Signature,
    },
    Encrypted {
        algo: u8,
        nonce: Nonce,
        data: Vec<u8>,
    },
}

impl Payload {
    //pub(crate) fn decode_plain(buf: &[u8], len: u16) -> nom::IResult<&[u8], (u32, u32, Vec<u8>)> {
    //    let (r, (dst_port, src_port)) = try_parse!(buf, ports_parse);
    //    let data_len = if src_port != dst_port { len - 4 } else { len };
    //    let (r, data) = try_parse!(r, take!(data_len));
    //    Ok((r, (src_port, dst_port, data.to_vec())))
    //}
    named_args!(pub decode_plain(len: u16)<(u32, u32, Vec<u8>)>,
        do_parse!(
            ports: ports_parse >>
            data_len: alt_complete!(cond_reduce!(ports.1 != ports.0, value!(len - 4)) | value!(len)) >>
            data: take!(data_len) >>
            (ports.1, ports.0, data.to_vec())
        )
    );

    //pub(crate) fn decode_signed(
    //    buf: &[u8],
    //    len: u16,
    //) -> nom::IResult<&[u8], (u8, u32, u32, Signature, Vec<u8>)> {
    //    let (r, algo) = try_parse!(buf, be_u8);
    //    let (r, (dst_port, src_port)) = try_parse!(r, ports_parse);
    //    let data_len = if src_port != dst_port { len - 4 } else { len };
    //    let (r, sig) = try_parse!(r, count_fixed!(u8, be_u8, SIGNATUREBYTES));
    //    let (r, data) = try_parse!(r, take!(data_len));
    //    Ok((r, (algo, src_port, dst_port, Signature(sig), data.to_vec())))
    //}

    named_args!(pub decode_signed(len: u16)<(u8, u32, u32, Signature, Vec<u8>)>,
        do_parse!(
            algo: be_u8 >>
            ports: ports_parse >>
            data_len: alt_complete!(cond_reduce!(ports.1 != ports.0, value!(len - 4)) | value!(len)) >>
            sig: count_fixed!(u8, be_u8, SIGNATUREBYTES) >>
            data: take!(data_len) >>
            (algo, ports.1, ports.0, Signature(sig), data.to_vec())
        )
    );


    named_args!(pub decode_encrypted(len: u16)<(u8, Nonce, Vec<u8>)>,
        do_parse!(
            algo: be_u8 >>
            nonce: count_fixed!(u8, be_u8, NONCEBYTES) >>
            data: take!(len) >>
            (algo, Nonce(nonce), data.to_vec())
        )
    );

    pub fn encode<A: BufMut>(&self, buf: &mut A) -> Result<usize> {
        match *self {
            Payload::Plain {
                src_port,
                dst_port,
                ref data,
            } => {
                let w = buf.remaining_mut();
                let mut port = dst_port << 1;
                if src_port == dst_port {
                    port |= 1u32;
                }
                buf.put_u32::<BigEndian>(port);
                if src_port != dst_port {
                    buf.put_u32::<BigEndian>(src_port);
                }
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
            Payload::Signed {
                algo,
                src_port,
                dst_port,
                ref sig,
                ref data,
            } => {
                let w = buf.remaining_mut();
                buf.put_u8(algo);
                let mut port = dst_port << 1;
                if src_port == dst_port {
                    port |= 1u32;
                }
                buf.put_u32::<BigEndian>(port);
                if src_port != dst_port {
                    buf.put_u32::<BigEndian>(src_port);
                }
                buf.put_slice(sig.as_ref());
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
            Payload::Encrypted {
                algo,
                ref nonce,
                ref data,
            } => {
                let w = buf.remaining_mut();
                buf.put_u8(algo);
                buf.put_slice(nonce.as_ref());
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
        }
    }

    pub fn encrypt<A: Into<Addr>>(&self, to: A, from: &LocalAddr) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } | Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Plain {
                src_port,
                dst_port,
                ref data,
            } => {
                let mut buf = Vec::new();
                let mut port = dst_port << 1;
                if src_port == dst_port {
                    port |= 1u32;
                }
                buf.put_u32::<BigEndian>(port);
                if src_port != dst_port {
                    buf.put_u32::<BigEndian>(src_port);
                }
                buf.put_slice(data);
                let (nonce, ciphertext) = if let Ok((nonce, ciphertext)) = from.encrypt(&buf, to) {
                    (nonce, ciphertext)
                } else {
                    return Err(Error::Encrypt);
                };
                Ok(Payload::Encrypted {
                    algo: 1,
                    nonce: nonce,
                    data: ciphertext,
                })
            }
        }
    }
    pub fn decrypt<A: Into<Addr>>(&self, to: &LocalAddr, from: A) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } | Payload::Plain { .. } => Err(Error::PacketNeedsEncrypted),
            Payload::Encrypted {
                nonce, ref data, ..
            } => match to.decrypt(data, &nonce, from) {
                Err(_) => Err(Error::Decrypt),
                Ok(buf) => match Payload::decode_plain(buf.as_slice(), buf.len() as u16 - 4) {
                    Ok((_, (src_port, dst_port, data))) => Ok(Payload::Plain {
                        src_port: src_port,
                        dst_port: dst_port,
                        data: data,
                    }),
                    _ => Err(Error::PayloadDecodeEncrypted),
                },
            },
        }
    }

    pub fn sign(&self, from: &LocalAddr) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } | Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Plain {
                src_port,
                dst_port,
                ref data,
                ..
            } => Ok(Payload::Signed {
                algo: 1,
                src_port: src_port,
                dst_port: dst_port,
                data: data.clone(),
                sig: from.sign(data),
            }),
        }
    }
    pub fn verify<A: Into<Addr>>(&self, from: A) -> Result<()> {
        match *self {
            Payload::Plain { .. } | Payload::Encrypted { .. } => Err(Error::PacketNeedsSigned),
            Payload::Signed {
                ref data, ref sig, ..
            } => LocalAddr::verify(sig, data, from),
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Payload::Signed {
                ref src_port,
                ref dst_port,
                ref data,
                ..
            } => {
                if src_port == dst_port {
                    5 + SIGNATUREBYTES + data.len()
                } else {
                    9 + SIGNATUREBYTES + data.len()
                }
            }
            Payload::Plain {
                ref src_port,
                ref dst_port,
                ref data,
            } => {
                if src_port == dst_port {
                    4 + data.len()
                } else {
                    8 + data.len()
                }
            }
            Payload::Encrypted { ref data, .. } => 1 + NONCEBYTES + data.len(),
        }
    }

    pub(crate) fn data_len(&self) -> usize {
        match *self {
            Payload::Signed { ref data, .. }
            | Payload::Plain { ref data, .. }
            | Payload::Encrypted { ref data, .. } => data.len(),
        }
    }

    pub fn contents(&self) -> Result<&[u8]> {
        match *self {
            Payload::Signed { .. } | Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Plain { ref data, .. } => Ok(data),
        }
    }
}

pub(crate) fn ports_parse(i: &[u8]) -> nom::IResult<&[u8], (u32, u32)> {
    let (r, mut dst_port) = try_parse!(i, be_u32);
    let (r, dst_port, src_port) = if dst_port.nth_bit_is_set(1) {
        dst_port >>= 1;
        (r, dst_port, dst_port)
    } else {
        dst_port >>= 1;
        let (r, src_port) = try_parse!(r, be_u32);
        (r, dst_port, src_port)
    };
    Ok((r, (dst_port, src_port)))
}

//named!(ports_parse<(u32, u32)>,
//    do_parse!(
//        bits: be_u32 >>
//        dst_port: value!(bits.shr(1)) >>
//        src_port: alt_complete!(cond_reduce!(bits.nth_bit_is_set(1), value!(dst_port)) | be_u32) >>
//        (dst_port, src_port)
//    )
//);
        

#[cfg(test)]
mod tests {
    use super::*;
    use addr::*;

    #[test]
    fn encrypt_decrypt() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: vec![0, 1, 2, 3, 4, 5],
        };
        let p2 = p1.clone();
        let s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let p1 = p1.encrypt(&s1, &mut s2).unwrap();
        let p1 = p1.decrypt(&mut s2, &s1).unwrap();

        assert!(p1 == p2)
    }

    #[test]
    fn sign_verify() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: vec![0, 1, 2, 3, 4, 5],
        };
        let s1 = LocalAddr::new();
        let p1 = p1.sign(&s1).unwrap();
        assert!(p1.verify(&s1).is_ok())
    }

    #[test]
    fn decode_plain() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: vec![0, 1, 2, 3, 4, 5],
        };
        let p2 = p1.clone();
        let mut buf = vec![];
        p1.encode(&mut buf).unwrap();
        if let Ok((_, (src_port, dst_port, data))) =
            Payload::decode_plain(buf.as_slice(), (buf.len() - 4) as u16)
        {
            let p1d = Payload::Plain {
                src_port: src_port,
                dst_port: dst_port,
                data: data,
            };
            assert!(p2 == p1d)
        } else {
            panic!()
        }
    }

    #[test]
    fn decode_encrypted() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: vec![0, 1, 2, 3, 4, 5],
        };
        let p2 = p1.clone();
        let s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let p1 = p1.encrypt(&s1, &mut s2).unwrap();
        let mut buf = vec![];
        p1.encode(&mut buf).unwrap();
        if let Ok((_, (algo, nonce, data))) =
            Payload::decode_encrypted(buf.as_slice(), (buf.len() - 1 - NONCEBYTES) as u16)
        {
            let p1d = Payload::Encrypted {
                algo: algo,
                nonce: nonce,
                data: data,
            };
            let p1d = p1d.decrypt(&mut s2, &s1).unwrap();
            assert!(p2 == p1d)
        } else {
            panic!()
        }
    }

    #[test]
    fn decode_signed() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: vec![0, 1, 2, 3, 4, 5],
        };
        let s1 = LocalAddr::new();
        let p1 = p1.sign(&s1).unwrap();
        let mut buf = vec![];
        p1.encode(&mut buf).unwrap();
        if let Ok((_, (algo, src_port, dst_port, sig, data))) =
            Payload::decode_signed(buf.as_slice(), (buf.len() - 5 - SIGNATUREBYTES) as u16)
        {
            let p1d = Payload::Signed {
                algo: algo,
                src_port: src_port,
                dst_port: dst_port,
                sig: sig,
                data: data,
            };
            assert!(p1d.verify(&s1).is_ok())
        } else {
            panic!()
        }
    }
}
