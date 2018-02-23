//! The traits for overlay interfaces that can be added to a `Protocol` object.
use std::fmt::Debug;
use futures::{Sink, Stream};
use frame::Frame;
use error::Error;

/// The trait for an MDP overlay `Interface`.
pub trait Interface: Stream + Sink + Send + Debug {
    fn last_sent_seq(&self) -> i8;
}

/// Trait object alias for an `Interface`.
pub type BoxInterface =
    Box<Interface<Item = Frame, Error = Error, SinkItem = Frame, SinkError = Error>>;
