use nom::{IResult, ErrorKind};
use sodiumoxide::randombytes::randombytes_into;

pub const BIDBYTES: usize = 8;
pub const BID_EMPTY: Bid = Bid([0; BIDBYTES]);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Bid(pub [u8; BIDBYTES]);

impl Bid {
    pub fn new() -> Bid {
        let mut b = BID_EMPTY;
        randombytes_into(&mut b.0);
        b
    }
    pub fn from_slice(buf: &[u8]) -> Option<Bid> {
        if buf.len() != BIDBYTES {
            return None;
        }
        let mut x = Bid([0; BIDBYTES]);
        {
            let Bid(ref mut bytes) = x;
            for (bytesi, &bufi) in bytes.iter_mut().zip(buf.iter()) {
                *bytesi = bufi
            }
        }
        Some(x)
    }
}

impl AsRef<[u8]> for Bid {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

pub(crate) fn bid_parse(i: &[u8]) -> IResult<&[u8], Bid> {
    let (r, bytes) = try_parse!(i, take!(BIDBYTES));
    if let Some(x) = Bid::from_slice(bytes) {
        IResult::Done(r, x)
    } else {
        IResult::Error(ErrorKind::Custom(42))
    }
}

