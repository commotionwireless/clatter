//! Address primitives for working with MDP.
use libc::c_int;
use hex_slice::AsHex;
use nom::{ErrorKind, IResult};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
pub(crate) use sodiumoxide::crypto::box_::{Nonce, NONCEBYTES};
pub(crate) use sodiumoxide::crypto::sign::{Signature, SIGNATUREBYTES};
use std::collections::hash_map::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use error::{Error, Result};

/// The number of bytes in a complete MDP address.
pub const ADDRBYTES: usize = 32;

/// The empty or null address, this is equivalent to a public-key of all zeroes.
pub const ADDR_EMPTY: Addr = Addr {
    sign: sign::PublicKey([0u8; sign::PUBLICKEYBYTES]),
    crypt: box_::PublicKey([0u8; box_::PUBLICKEYBYTES]),
    length: sign::PUBLICKEYBYTES as u8,
};

/// The broadcast address, this is equivalent to a public-key of all ones.
pub const ADDR_BROADCAST: Addr = Addr {
    sign: sign::PublicKey([1u8; sign::PUBLICKEYBYTES]),
    crypt: box_::PublicKey([1u8; box_::PUBLICKEYBYTES]),
    length: sign::PUBLICKEYBYTES as u8,
};

extern "C" {
    fn crypto_sign_ed25519_pk_to_curve25519(
        pk_crypt: *mut [u8; box_::PUBLICKEYBYTES],
        pk_sign: *const [u8; sign::PUBLICKEYBYTES],
    ) -> c_int;
    fn crypto_sign_ed25519_sk_to_curve25519(
        sk_crypt: *mut [u8; box_::SECRETKEYBYTES],
        sk_sign: *const [u8; sign::SECRETKEYBYTES],
    ) -> c_int;
}

fn ed25519_pk_to_curve25519(
    &sign::PublicKey(ref pk_sign): &sign::PublicKey,
) -> Result<box_::PublicKey> {
    unsafe {
        let mut pk_crypt = [0u8; box_::PUBLICKEYBYTES];
        match crypto_sign_ed25519_pk_to_curve25519(&mut pk_crypt, pk_sign) {
            0 => Ok(box_::PublicKey(pk_crypt)),
            _ => Err(Error::ConvertPublicKey),
        }
    }
}

fn ed25519_sk_to_curve25519(
    &sign::SecretKey(ref sk_sign): &sign::SecretKey,
) -> Result<box_::SecretKey> {
    unsafe {
        let mut sk_crypt = [0u8; box_::SECRETKEYBYTES];
        match crypto_sign_ed25519_sk_to_curve25519(&mut sk_crypt, sk_sign) {
            0 => Ok(box_::SecretKey(sk_crypt)),
            _ => Err(Error::ConvertPrivateKey),
        }
    }
}

/// An MDP address.
///
/// This is a remote MDP network address. It is equivalent to a public key, and is commonly derived
/// from a [`LocalAddr`][link]
///
/// [link] = #struct.LocalAddr
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    sign: sign::PublicKey,
    crypt: box_::PublicKey,
    length: u8,
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.sign.0.as_hex())
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.sign.0.as_hex())
    }
}

impl Addr {
    pub fn len(&self) -> usize {
        self.length as usize
    }
}

impl<'a> From<&'a Addr> for Addr {
    fn from(s: &'a Addr) -> Self {
        *s
    }
}

impl From<LocalAddr> for Addr {
    fn from(s: LocalAddr) -> Self {
        Addr {
            sign: s.0.pk_sign,
            crypt: s.0.pk_crypt,
            length: sign::PUBLICKEYBYTES as u8,
        }
    }
}

impl<'a> From<&'a LocalAddr> for Addr {
    fn from(s: &'a LocalAddr) -> Self {
        Addr {
            sign: s.0.pk_sign,
            crypt: s.0.pk_crypt,
            length: sign::PUBLICKEYBYTES as u8,
        }
    }
}

impl<'a> From<&'a mut LocalAddr> for Addr {
    fn from(s: &'a mut LocalAddr) -> Self {
        Addr {
            sign: s.0.pk_sign,
            crypt: s.0.pk_crypt,
            length: sign::PUBLICKEYBYTES as u8,
        }
    }
}

impl AsRef<[u8]> for Addr {
    fn as_ref(&self) -> &[u8] {
        self.sign.as_ref()
    }
}

/// A socket address.
///
/// This is a combination of an `Addr` and a 32-bit port number on the MDP network.
#[derive(Copy, Clone, PartialEq)]
pub struct SocketAddr {
    pub addr: Addr,
    pub port: u32,
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl<A: Into<Addr>> From<(A, u32)> for SocketAddr {
    fn from((addr, port): (A, u32)) -> Self {
        SocketAddr {
            addr: addr.into(),
            port: port,
        }
    }
}

impl SocketAddr {
    pub fn addr(&self) -> &Addr {
        &self.addr
    }

    pub fn port(&self) -> u32 {
        self.port
    }
}

/// A local MDP address.
///
/// This is an MDP address local to this machine, and represents a public/private key pair. It is
/// required for binding a socket or encrypting and verifying messages.
#[derive(Clone)]
pub struct LocalAddr(pub(crate) Arc<LocalAddrInfo>);

impl fmt::Display for LocalAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for LocalAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl LocalAddr {
    pub fn new() -> LocalAddr {
        let (pk_sign, sk_sign) = sign::gen_keypair();
        let pk_crypt = ed25519_pk_to_curve25519(&pk_sign).unwrap();
        let sk_crypt = ed25519_sk_to_curve25519(&sk_sign).unwrap();
        LocalAddr(Arc::new(LocalAddrInfo {
            pk_sign: pk_sign,
            sk_sign: sk_sign,
            pk_crypt: pk_crypt,
            sk_crypt: sk_crypt,
            pre: RwLock::new(HashMap::new()),
        }))
    }

    pub fn encrypt<B: AsRef<[u8]>, A: Into<Addr>>(
        &self,
        buf: &B,
        addr: A,
    ) -> Result<(Nonce, Vec<u8>)> {
        let a = addr.into();
        let nonce = box_::gen_nonce();
        let b = buf.as_ref();
        if let Some(v) = self.0.try_encrypt(b, &nonce, &a) {
            Ok((nonce, v))
        } else {
            self.0.add_pre(&a);
            if let Some(v) = self.0.try_encrypt(b, &nonce, &a) {
                Ok((nonce, v))
            } else {
                Err(Error::Encrypt)
            }
        }
    }

    pub fn decrypt<B: AsRef<[u8]>, A: Into<Addr>>(
        &self,
        buf: &B,
        nonce: &Nonce,
        addr: A,
    ) -> Result<Vec<u8>> {
        let a = addr.into();
        let b = buf.as_ref();
        match self.0.try_decrypt(b, nonce, &a) {
            Some(r) => r,
            _ => {
                self.0.add_pre(&a);
                if let Some(r) = self.0.try_decrypt(b, nonce, &a) {
                    r
                } else {
                    Err(Error::Encrypt)
                }
            }
        }
    }

    pub fn sign<A: AsRef<[u8]>>(&self, buf: &A) -> Signature {
        sign::sign_detached(buf.as_ref(), &self.0.sk_sign)
    }

    pub fn verify<A: AsRef<[u8]>, B: Into<Addr>>(sig: &Signature, buf: &A, addr: B) -> Result<()> {
        if sign::verify_detached(sig, buf.as_ref(), &addr.into().sign) {
            Ok(())
        } else {
            Err(Error::Verify)
        }
    }
}

pub(crate) struct LocalAddrInfo {
    pk_sign: sign::PublicKey,
    sk_sign: sign::SecretKey,
    pk_crypt: box_::PublicKey,
    sk_crypt: box_::SecretKey,
    pre: RwLock<HashMap<box_::PublicKey, box_::PrecomputedKey>>,
}

impl fmt::Display for LocalAddrInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.pk_sign.0.as_hex())
    }
}

impl fmt::Debug for LocalAddrInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.pk_sign.0.as_hex())
    }
}

impl LocalAddrInfo {
    fn try_encrypt(&self, buf: &[u8], nonce: &Nonce, addr: &Addr) -> Option<Vec<u8>> {
        let lock = self.pre.read().unwrap();
        if let Some(key) = lock.get(&addr.crypt.to_owned()) {
            Some(box_::seal_precomputed(buf, nonce, key))
        } else {
            None
        }
    }

    fn try_decrypt(&self, buf: &[u8], nonce: &Nonce, addr: &Addr) -> Option<Result<Vec<u8>>> {
        let lock = self.pre.read().unwrap();
        if let Some(key) = lock.get(&addr.crypt.to_owned()) {
            match box_::open_precomputed(buf, nonce, key) {
                Ok(v) => Some(Ok(v)),
                _ => Some(Err(Error::Encrypt)),
            }
        } else {
            None
        }
    }

    fn add_pre(&self, addr: &Addr) {
        let mut lock = self.pre.write().unwrap();
        lock.insert(
            addr.crypt.to_owned(),
            box_::precompute(&addr.crypt.to_owned(), &self.sk_crypt),
        );
    }
}

pub(crate) fn address_parse(i: &[u8]) -> IResult<&[u8], Addr> {
    let (r, bytes) = try_parse!(i, take!(ADDRBYTES));
    if let Some(x) = sign::PublicKey::from_slice(bytes) {
        IResult::Done(
            r,
            Addr {
                sign: x,
                crypt: ed25519_pk_to_curve25519(&x).unwrap(),
                length: sign::PUBLICKEYBYTES as u8,
            },
        )
    } else {
        IResult::Error(ErrorKind::Custom(42))
    }
}
