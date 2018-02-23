// Borrowed from tokio_core
macro_rules! try_nb {
    ($e:expr) => (match $e {
        Ok(t) => t,
        Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
            return Ok(::futures::Async::NotReady)
        }
        Err(e) => return Err(e.into()),
    })
}

pub(crate) trait BitMask {
    fn nth_bit_is_set(&self, nth: u32) -> bool;
}

impl BitMask for u32 {
    fn nth_bit_is_set(&self, nth: u32) -> bool {
        if nth > 0 && nth <= 32 {
            let bit = 1 << (nth - 1);
            *self & bit == bit
        } else {
            false
        }
    }
}

impl BitMask for u64 {
    fn nth_bit_is_set(&self, nth: u32) -> bool {
        if nth > 0 && nth <= 64 {
            let bit = 1 << (nth - 1);
            *self & bit == bit
        } else {
            false
        }
    }
}

