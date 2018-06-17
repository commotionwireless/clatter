//! An analogue of UDP on a traditional IP network, MDP is an encrypted networking protocol that 
//! uses 256-bit public keys in the ed25519 elliptic-curve keyspace instead of IP addresses for 
//! routing. MDP is designed to provide a balance of confidentiality and brevity that is optimal 
//! for unreliable radio networks. MDP uses per-hop message aggregation and retransmission and 
//! numerous tricks for address abbreviation and deduplication to provide a high degree of 
//! redundancy and a low degree of bandwidth overhead. MDP also provides smart broadcast flooding 
//! and link-state mesh routing integrated as part of the protocol. It is designed to be agnostic 
//! of its transport medium; the current overlay implementation runs on top of UDP/IP, but will be 
//! expanded to other transport mediums in the future. The version of MDP in Clatter is not 
//! currently as feature-rich as the main version in Serval. For more information on MDP, see 
//! Serval's [documentation]
//! (https://github.com/servalproject/serval-dna/blob/development/doc/Mesh-Datagram-Protocol.md).

#[macro_use]
extern crate bitflags;
extern crate bytes;
#[macro_use]
extern crate cookie_factory;
#[macro_use]
extern crate futures;
extern crate hex_slice;
extern crate libc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate petgraph;
extern crate sodiumoxide;
extern crate stable_vec;
extern crate time;
extern crate tokio_codec;
extern crate tokio_timer;
extern crate tokio_udp;

#[macro_use]
mod util;
pub mod addr;
mod broadcast;
pub mod error;
mod frame;
pub mod interface;
pub mod overlay;
mod packet;
mod payload;
pub mod protocol;
mod qos;
mod routing;
pub mod services;
pub mod socket;
