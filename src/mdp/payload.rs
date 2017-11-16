use bytes::{BufMut, BigEndian};
use nom::{be_u8, be_u32, IResult};
use std::vec::Vec;
use std::u16;
use mdp::error::{Error, Result};
use mdp::addr::{Addr, LocalAddr, Nonce, NONCEBYTES, Signature, SIGNATUREBYTES};

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
    named_args!(pub deserialize_plain(len: u16)<(u32, u32, Vec<u8>)>,
        do_parse!(
            src_port: be_u32 >>
            dst_port: be_u32 >>
            data: take!(len) >>
            (src_port, dst_port, data.to_vec())
        )
    );

    named_args!(pub deserialize_signed(len: u16)<(u8, u32, u32, Signature, Vec<u8>)>,
        do_parse!(
            algo: be_u8 >>
            src_port: be_u32 >>
            dst_port: be_u32 >>
            sig: count_fixed!(u8, be_u8, SIGNATUREBYTES) >>
            data: take!(len) >>
            (algo, src_port, dst_port, Signature(sig), data.to_vec())
        )
    );

    named_args!(pub deserialize_encrypted(len: u16)<(u8, Nonce, Vec<u8>)>,
        do_parse!(
            algo: be_u8 >>
            nonce: count_fixed!(u8, be_u8, NONCEBYTES) >>
            data: take!(len) >>
            (algo, Nonce(nonce), data.to_vec())
        )
    );

    pub fn serialize<A: BufMut>(&self, buf: &mut A) -> Result<usize> {
        match *self {
            Payload::Plain { src_port, dst_port, ref data } => {
                let w = buf.remaining_mut();
                buf.put_u32::<BigEndian>(src_port);
                buf.put_u32::<BigEndian>(dst_port);
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
            Payload::Signed { algo, src_port, dst_port, ref sig, ref data } => {
                let w = buf.remaining_mut();
                buf.put_u8(algo);
                buf.put_u32::<BigEndian>(src_port);
                buf.put_u32::<BigEndian>(dst_port);
                buf.put_slice(sig.as_ref());
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
            Payload::Encrypted { algo, ref nonce, ref data } => {
                let w = buf.remaining_mut();
                buf.put_u8(algo);
                buf.put_slice(nonce.as_ref());
                buf.put_slice(data);
                Ok(w - buf.remaining_mut())
            }
        }
    }

    pub fn encrypt<A: Into<Addr>>(&self, to: A, from: &mut LocalAddr) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } => return Err(Error::PacketNeedsPlain),
            Payload::Encrypted { .. } => return Err(Error::PacketNeedsPlain),
            Payload::Plain { src_port, dst_port, ref data } => {
                let mut buf = Vec::new();
                buf.put_u32::<BigEndian>(src_port);
                buf.put_u32::<BigEndian>(dst_port);
                buf.put_slice(data);
                let (nonce, ciphertext) = from.encrypt(&mut buf, to);
                return Ok(Payload::Encrypted {
                    algo: 1,
                    nonce: nonce,
                    data: ciphertext,
                });
            }
        }
    }
    pub fn decrypt<A: Into<Addr>>(&self, to: &mut LocalAddr, from: A) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } => Err(Error::PacketNeedsEncrypted),
            Payload::Plain { .. } => Err(Error::PacketNeedsEncrypted),
            Payload::Encrypted { nonce, ref data, .. } => {
                match to.decrypt(data, &nonce, from) {
                    Err(_) => Err(Error::Decrypt),
                    Ok(buf) => {
                        match Payload::deserialize_plain(buf.as_slice(), buf.len() as u16 - 8){
                            IResult::Done(_, (src_port, dst_port, data)) => Ok(
                                    Payload::Plain {
                                        src_port: src_port,
                                        dst_port: dst_port,
                                        data: data
                                    }),
                            _ => Err(Error::PayloadDeserializeEncrypted),
                        }
                    }
                }
            } 
        }
    }

    pub fn sign(&self, from: &LocalAddr) -> Result<Payload> {
        match *self {
            Payload::Signed { .. } => Err(Error::PacketNeedsPlain),
            Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Plain { src_port, dst_port, ref data, .. } => {
                Ok(Payload::Signed {
                    algo: 1,
                    src_port: src_port,
                    dst_port: dst_port,
                    data: data.clone(),
                    sig: from.sign(data)
                })
            }
        }
    }
    pub fn verify<A: Into<Addr>>(&self, from: A) -> Result<()> {
        match *self {
            Payload::Plain { .. } => Err(Error::PacketNeedsSigned),
            Payload::Encrypted { .. } => Err(Error::PacketNeedsSigned),
            Payload::Signed { ref data, ref sig, .. } => {
                LocalAddr::verify(sig, data, from)
            }
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Payload::Signed { ref data, .. } => {
                9 + SIGNATUREBYTES + data.len()
            },
            Payload::Plain { ref data, .. } => 8 + data.len(),
            Payload::Encrypted { ref data, .. } => 1 + NONCEBYTES + data.len(),
        }
    }

    pub(crate) fn data_len(&self) -> usize {
        match *self {
            Payload::Signed { ref data, .. } => data.len(),
            Payload::Plain { ref data, .. } => data.len(),
            Payload::Encrypted { ref data, .. } => data.len(),
        }
    }

    pub fn contents(&self) -> Result<&[u8]> {
        match *self {
            Payload::Signed { .. } => Err(Error::PacketNeedsPlain),
            Payload::Encrypted { .. } => Err(Error::PacketNeedsPlain),
            Payload::Plain { ref data, .. } => Ok(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdp::addr::*;

    #[test]
    fn encrypt_decrypt() {
        let p1 = Payload::Plain { src_port: 80, dst_port: 80, data: vec![0, 1, 2, 3, 4, 5] };
        let p2 = p1.clone();
        let s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let p1 = p1.encrypt(&s1, &mut s2).unwrap();
        let p1 = p1.decrypt(&mut s2, &s1).unwrap();

        assert!(p1 == p2)
    }

    #[test]
    fn sign_verify() {
        let p1 = Payload::Plain { src_port: 80, dst_port: 80, data: vec![0, 1, 2, 3, 4, 5] };
        let s1 = LocalAddr::new();
        let p1 = p1.sign(&s1).unwrap();
        assert!(p1.verify(&s1).is_ok())
    }

    #[test]
    fn deserialize_plain() {
        let p1 = Payload::Plain { src_port: 80, dst_port: 80, data: vec![0, 1, 2, 3, 4, 5] };
        let p2 = p1.clone();
        let mut buf = vec![];
        p1.serialize(&mut buf).unwrap();
        if let IResult::Done(_, (src_port, dst_port, data)) = Payload::deserialize_plain(
            buf.as_slice(), (buf.len() - 8) as u16) {
            let p1d = Payload::Plain { src_port: src_port, dst_port: dst_port, data: data };
            assert!(p2 == p1d)
        } else {
            panic!()
        }

    }

    #[test]
    fn deserialize_encrypted() {
        let p1 = Payload::Plain { src_port: 80, dst_port: 80, data: vec![0, 1, 2, 3, 4, 5] };
        let p2 = p1.clone();
        let s1 = LocalAddr::new();
        let mut s2 = LocalAddr::new();
        let p1 = p1.encrypt(&s1, &mut s2).unwrap();
        let mut buf = vec![];
        p1.serialize(&mut buf).unwrap();
        if let IResult::Done(_, (algo, nonce, data)) = Payload::deserialize_encrypted(
            buf.as_slice(), (buf.len() - 1 - NONCEBYTES) as u16) {
            let p1d = Payload::Encrypted { algo: algo, nonce: nonce, data: data };
            let p1d = p1d.decrypt(&mut s2, &s1).unwrap();
            assert!(p2 == p1d)
        } else {
            panic!()
        }

    }

    #[test]
    fn deserialize_signed() {
        let p1 = Payload::Plain { src_port: 80, dst_port: 80, data: vec![0, 1, 2, 3, 4, 5] };
        let s1 = LocalAddr::new();
        let p1 = p1.sign(&s1).unwrap();
        let mut buf = vec![];
        p1.serialize(&mut buf).unwrap();
        if let IResult::Done(_, (algo, src_port, dst_port, sig, data)) = 
            Payload::deserialize_signed(buf.as_slice(), (buf.len() - 9 - SIGNATUREBYTES) as u16) {
                let p1d = Payload::Signed { algo: algo, src_port: src_port, dst_port: dst_port, 
                    sig: sig, data: data };
                assert!(p1d.verify(&s1).is_ok())
        } else {
            panic!()
        }

    }
}
