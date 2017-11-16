use libc::c_int;
use nom::{IResult, ErrorKind};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
pub use sodiumoxide::crypto::box_::{Nonce, NONCEBYTES};
pub use sodiumoxide::crypto::sign::{Signature, SIGNATUREBYTES};
use std::collections::hash_map::HashMap;
use mdp::error::{Error, Result};

pub const ADDRBYTES: usize = 32;
pub const ADDR_EMPTY: Addr = Addr {
    sign: sign::PublicKey([0u8; sign::PUBLICKEYBYTES]),
    crypt: box_::PublicKey([0u8; box_::PUBLICKEYBYTES])
};

pub const ADDR_BROADCAST: Addr = Addr {
    sign: sign::PublicKey([1u8; sign::PUBLICKEYBYTES]),
    crypt: box_::PublicKey([1u8; box_::PUBLICKEYBYTES])
};

extern "C" {
    fn crypto_sign_ed25519_pk_to_curve25519(pk_crypt: *mut [u8; box_::PUBLICKEYBYTES], pk_sign: *const [u8; sign::PUBLICKEYBYTES]) -> c_int;
    fn crypto_sign_ed25519_sk_to_curve25519(sk_crypt: *mut [u8; box_::SECRETKEYBYTES], sk_sign: *const [u8; sign::SECRETKEYBYTES]) -> c_int;
}

fn ed25519_pk_to_curve25519(&sign::PublicKey(ref pk_sign): &sign::PublicKey) -> Result<box_::PublicKey> {
    unsafe {
        let mut pk_crypt = [0u8; box_::PUBLICKEYBYTES];
        match crypto_sign_ed25519_pk_to_curve25519(&mut pk_crypt, pk_sign) {
            0 => Ok(box_::PublicKey(pk_crypt)),
            _ => Err(Error::ConvertPublicKey)
        }
    }
}

fn ed25519_sk_to_curve25519(&sign::SecretKey(ref sk_sign): &sign::SecretKey) -> Result<box_::SecretKey> {
    unsafe {
        let mut sk_crypt = [0u8; box_::SECRETKEYBYTES];
        match crypto_sign_ed25519_sk_to_curve25519(&mut sk_crypt, sk_sign) {
            0 => Ok(box_::SecretKey(sk_crypt)),
            _ => Err(Error::ConvertPrivateKey)
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    sign: sign::PublicKey,
    crypt: box_::PublicKey
}

impl From<LocalAddr> for Addr {
    fn from(s: LocalAddr) -> Self {
        Addr {
            sign: s.pk_sign,
            crypt: s.pk_crypt
        }
    }
}

impl<'a> From<&'a LocalAddr> for Addr {
    fn from(s: &'a LocalAddr) -> Self {
        Addr {
            sign: s.pk_sign,
            crypt: s.pk_crypt
        }
    }
}

impl AsRef<[u8]> for Addr {
    fn as_ref(&self) -> &[u8] {
        &self.sign.as_ref()
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct SocketAddr {
    pub addr: Addr,
    pub port: u32,
}

impl<A: Into<Addr>> From<(A, u32)> for SocketAddr {
    fn from((addr, port): (A, u32)) -> Self {
        SocketAddr {
            addr: addr.into(),
            port: port
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalAddr {
    pk_sign: sign::PublicKey,
    sk_sign: sign::SecretKey,
    pk_crypt: box_::PublicKey,
    sk_crypt: box_::SecretKey,
    pre: HashMap<box_::PublicKey, box_::PrecomputedKey>
}

impl LocalAddr {
    pub fn new() -> LocalAddr {
        let (pk_sign, sk_sign) = sign::gen_keypair();
        let pk_crypt = ed25519_pk_to_curve25519(&pk_sign).unwrap();
        let sk_crypt = ed25519_sk_to_curve25519(&sk_sign).unwrap();
        LocalAddr {
            pk_sign: pk_sign,
            sk_sign: sk_sign,
            pk_crypt: pk_crypt,
            sk_crypt: sk_crypt,
            pre: HashMap::new(),
        }
    }

    fn precompute(&mut self, addr: &Addr) -> &box_::PrecomputedKey {
        self.pre.entry(addr.crypt.to_owned()).or_insert(box_::precompute(&addr.crypt, &self.sk_crypt))
    }

    pub fn encrypt<A: AsRef<[u8]>, B: Into<Addr>>(&mut self, buf: &mut A, addr: B) -> (Nonce, Vec<u8>) {
        let nonce = box_::gen_nonce();
        let key = self.precompute(&addr.into());
        (nonce, box_::seal_precomputed(buf.as_ref(), &nonce, key))
    }

    pub fn decrypt<A: AsRef<[u8]>, B: Into<Addr>>(&mut self, buf: &A, nonce: &Nonce, addr: B) -> Result<Vec<u8>> {
        let key = self.precompute(&addr.into());
        match box_::open_precomputed(buf.as_ref(), nonce, key) {
            Err(_) => Err(Error::Decrypt),
            Ok(c) => Ok(c)
        }
    }

    pub fn sign<A: AsRef<[u8]>>(&self, buf: &A) -> Signature {
        sign::sign_detached(buf.as_ref(), &self.sk_sign)
    }

    pub fn verify<A: AsRef<[u8]>, B: Into<Addr>>(sig: &Signature, buf: &A, addr: B) -> Result<()> {
        match sign::verify_detached(sig, buf.as_ref(), &addr.into().sign) {
            false => Err(Error::Verify),
            true => Ok(())
        }
    }

}

pub(crate) fn address_parse(i: &[u8]) -> IResult<&[u8], Addr> {
    let (r, bytes) = try_parse!(i, take!(ADDRBYTES));
    if let Some(x) = sign::PublicKey::from_slice(bytes) {
        IResult::Done(r, Addr{ sign: x, crypt: ed25519_pk_to_curve25519(&x).unwrap() })
    } else {
        IResult::Error(ErrorKind::Custom(42))
    }
}
