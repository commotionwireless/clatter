use std::{ops::Shr, u16, vec::Vec};
use bytes::{BufMut, BytesMut};
use cookie_factory::GenError;
use nom::{be_u32, be_u8};

use addr::{Addr, LocalAddr, Nonce, Signature, NONCEBYTES, SIGNATUREBYTES};
use error::{Error, Result, GResult};
use util::BitMask;

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Plain {
        src_port: u32,
        dst_port: u32,
        data: BytesMut,
    },
    Signed {
        algo: u8,
        src_port: u32,
        dst_port: u32,
        data: BytesMut,
        sig: Signature,
    },
    Encrypted {
        algo: u8,
        nonce: Nonce,
        data: BytesMut,
    },
}

impl Payload {
    named_args!(pub decode_plain(len: u16)<(u32, u32, BytesMut)>,
        do_parse!(
            ports: ports_parse >>
            data_len: alt_complete!(cond_reduce!(ports.1 != ports.0, value!(len - 4)) | value!(len)) >>
            data: take!(data_len) >>
            (ports.1, ports.0, data.into())
        )
    );

    named_args!(pub decode_signed(len: u16)<(u8, u32, u32, Signature, BytesMut)>,
        do_parse!(
            algo: be_u8 >>
            ports: ports_parse >>
            data_len: alt_complete!(cond_reduce!(ports.1 != ports.0, value!(len - 4)) | value!(len)) >>
            sig: count_fixed!(u8, be_u8, SIGNATUREBYTES) >>
            data: take!(data_len) >>
            (algo, ports.1, ports.0, Signature(sig), data.into())
        )
    );

    named_args!(pub decode_encrypted(len: u16)<(u8, Nonce, BytesMut)>,
        do_parse!(
            algo: be_u8 >>
            nonce: count_fixed!(u8, be_u8, NONCEBYTES) >>
            data: take!(len) >>
            (algo, Nonce(nonce), data.into())
        )
    );

    pub fn encode<'b>(&self, buf: (&'b mut [u8], usize)) -> GResult<(&'b mut [u8], usize)> {
        match *self {
            Payload::Plain {
                src_port,
                dst_port,
                ref data,
            } => {
                let mut port = dst_port << 1;
                if src_port == dst_port {
                    port |= 1u32;
                }
                do_gen!(
                    buf,
                    gen_be_u32!(port) >>
                    gen_cond!(src_port != dst_port, gen_be_u32!(src_port)) >>
                    gen_slice!(data)
                )
            },
            Payload::Signed {
                algo,
                src_port,
                dst_port,
                ref sig,
                ref data,
            } => {
                let mut port = dst_port << 1;
                if src_port == dst_port {
                    port |= 1u32;
                }
                do_gen!(
                    buf,
                    gen_be_u8!(algo) >>
                    gen_be_u32!(port) >>
                    gen_cond!(src_port != dst_port, gen_be_u32!(src_port)) >>
                    gen_slice!(sig.as_ref()) >>
                    gen_slice!(data)
                )
            }
            Payload::Encrypted {
                algo,
                ref nonce,
                ref data,
            } => {
                do_gen!(
                    buf,
                    gen_be_u8!(algo) >>
                    gen_slice!(nonce.as_ref()) >>
                    gen_slice!(data)
                )
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
                buf.put_u32_be(port);
                if src_port != dst_port {
                    buf.put_u32_be(src_port);
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
                    data: ciphertext.into(),
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

    pub fn contents(&self) -> Result<&BytesMut> {
        match *self {
            Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Signed { ref data, .. }
            | Payload::Plain { ref data, .. } => Ok(data),
        }
    }

    pub fn contents_mut(&mut self) -> Result<&mut BytesMut> {
        match *self {
            Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Signed { ref mut data, .. } 
            | Payload::Plain { ref mut data, .. } => Ok(data),
        }
    }

    pub fn take(&mut self) -> Result<BytesMut> {
        match *self {
            Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Signed { ref mut data, .. } 
            | Payload::Plain { ref mut data, .. } => Ok(data.take()),
        }
    }
}

named!(ports_parse<(u32, u32)>,
    do_parse!(
        bits: be_u32 >>
        dst_port: value!(bits.shr(1)) >>
        src_port: alt_complete!(cond_reduce!(bits.nth_bit_is_set(1), value!(dst_port)) | be_u32) >>
        (dst_port, src_port)
    )
);

#[cfg(test)]
mod tests {
    use super::*;
    use addr::*;

    #[test]
    fn encrypt_decrypt() {
        let p1 = Payload::Plain {
            src_port: 80,
            dst_port: 80,
            data: BytesMut::from(&b"012345"[..]),
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
            data: BytesMut::from(&b"012345"[..]),
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
            data: BytesMut::from(&b"012345"[..]),
        };
        let p2 = p1.clone();
        let mut buf = vec![0; 250];
        let (buf, wr) = p1.encode((&mut buf, 0)).unwrap();
        if let Ok((_, (src_port, dst_port, data))) =
            Payload::decode_plain(buf, (wr - 4) as u16)
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
            data: BytesMut::from(&b"012345"[..]),
        };
        let p2 = p1.clone();
        let s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let p1 = p1.encrypt(&s1, &mut s2).unwrap();
        let mut buf = vec![0; 250];
        let (buf, wr) = p1.encode((&mut buf, 0)).unwrap();
        if let Ok((_, (algo, nonce, data))) =
            Payload::decode_encrypted(buf, (wr - 1 - NONCEBYTES) as u16)
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
            data: BytesMut::from(&b"012345"[..]),
        };
        let s1 = LocalAddr::new();
        let p1 = p1.sign(&s1).unwrap();
        let mut buf = vec![0; 250];
        let (buf, wr) = p1.encode((&mut buf, 0)).unwrap();
        if let Ok((_, (algo, src_port, dst_port, sig, data))) =
            Payload::decode_signed(buf, (wr - 5 - SIGNATUREBYTES) as u16)
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
