use std::collections::VecDeque;
use std::fmt;
use hex_slice::AsHex;
use sodiumoxide::randombytes::randombytes_into;

pub const BIDBYTES: usize = 8;
pub const BID_EMPTY: Id = Id([0; BIDBYTES]);

#[derive(Copy, Clone, PartialEq)]
pub struct Id(pub [u8; BIDBYTES]);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0.as_hex())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0.as_hex())
    }
}

impl Id {
    pub fn new() -> Id {
        let mut b = BID_EMPTY;
        randombytes_into(&mut b.0);
        b
    }
    pub fn from_slice(buf: &[u8]) -> Option<Id> {
        if buf.len() != BIDBYTES {
            return None;
        }
        let mut x = Id([0; BIDBYTES]);
        {
            let Id(ref mut bytes) = x;
            for (bytesi, &bufi) in bytes.iter_mut().zip(buf.iter()) {
                *bytesi = bufi
            }
        }
        Some(x)
    }
}

pub struct Window {
    inner: VecDeque<Id>,
    size: usize,
}

impl Window {
    pub fn new(size: usize) -> Window {
        Window {
            inner: VecDeque::with_capacity(size),
            size: size,
        }
    }

    pub fn recent(&mut self, bid: &Id) -> bool {
        if self.inner.contains(bid) {
            true
        } else {
            self.inner.push_back(*bid);
            if self.inner.len() > self.size {
                self.inner.pop_front();
            }
            false
        }
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//pub(crate) fn bid_parse(i: &[u8]) -> IResult<&[u8], Id> {
//    let (r, bytes) = try_parse!(i, take!(BIDBYTES));
//    if let Some(x) = Id::from_slice(bytes) {
//        IResult::Done(r, x)
//    } else {
//        IResult::Error(ErrorKind::Custom(42))
//    }
//}

named!(pub bid_parse<Id>,
    do_parse!(
        bytes: take!(BIDBYTES) >>
        id: expr_opt!(Id::from_slice(bytes)) >>
        (id)
    )
);



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_window() {
        let size = 2;
        let mut window = Window::new(size);
        let bid0 = Id::new();
        let bid1 = Id::new();
        let bid2 = Id::new();
        assert!(!window.recent(&bid0));
        assert!(!window.recent(&bid1));
        assert!(window.recent(&bid0));
        assert!(!window.recent(&bid2));
        assert!(!window.recent(&bid0));
    }
}
