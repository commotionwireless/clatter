pub trait BitMask {
    fn nth_bit_is_set(&self, nth: i8) -> bool;
}

impl BitMask for u32 {
    fn nth_bit_is_set(&self, nth: i8) -> bool {
        if nth > 0 && nth <= 32 {
            let bit = 1 << nth - 1;
            *self & bit == bit
        } else {
            false
        }
    }
}

impl BitMask for u64 {
    fn nth_bit_is_set(&self, nth: i8) -> bool {
        if nth > 0 && nth <= 64 {
            let bit = 1 << nth - 1;
            *self & bit == bit
        } else {
            false
        }
    }
}
