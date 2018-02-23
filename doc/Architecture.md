# Clatter Architecture

Clatter is a subproject of [Commotion Wireless](https://commotionwireless.net) to create a suite of software libraries making it easy for developers to add capabilities for offline mesh networking and delay-tolerant communication to their applications, and to do so in a way that is memory-safe and secure.

## Current Libraries

Clatter currently provides ports to the high-performance memory-safe systems programming language [Rust](https://rust-lang.org), pioneered by [Mozilla](https://mozilla.org), of implementations of secure mesh networking protocols implemented by the [Serval Project](https://servalproject.org), with the aim of making it easier to create applications that utilize Serval's technology and interoperate with Serval networks. These libraries include:

### The Mesh Datagram Protocol (MDP)

An analogue of UDP on a traditional IP network, MDP is an encrypted networking protocol that uses 256-bit public keys in the ed25519 elliptic-curve keyspace instead of IP addresses for routing. MDP is designed to provide a balance of confidentiality and brevity that is optimal for unreliable radio networks. MDP uses per-hop message aggregation and retransmission and numerous tricks for address abbreviation and deduplication to provide a high degree of redundancy and a low degree of bandwidth overhead. MDP also provides smart broadcast flooding and link-state mesh routing integrated as part of the protocol. It is designed to be agnostic of its transport medium; the current overlay implementation runs on top of UDP/IP, but will be expanded to other transport mediums in the future. The version of MDP in Clatter is not currently as feature-rich as the main version in Serval. For more information on MDP, see Serval's [documentation](https://github.com/servalproject/serval-dna/blob/development/doc/Mesh-Datagram-Protocol.md).

### The Mesh Streaming Protocol (MSP)

Just as MDP is an analogue to UDP, MSP is an analogue to TCP. MSP is built on top of MDP, providing additional guarantees such as a stateful, streaming connection between two MDP endpoints with in-order message delivery. For more information on MSP, see Serval's [documentation](https://github.com/servalproject/serval-dna/blob/development/doc/Mesh-Stream-Protocol.md).

### Rhizome

Rhizome is a service that runs on top of MDP and MSP, which provides a delay-tolerant service for synchronizing "bundles" of data between different nodes in the network. This can be used for, amongst other things, file transfer and messaging within a network that otherwise may be sparsely connected. Rhizome uses its own Bundle IDs in the 256-bit ed25519 keyspace in addition to MDP addresses. Rhizome's internals are currently being rewritten by the Serval Project to accomodate low-bandwidth packet radio links, and the Rhizome tools in Clatter are provided as a proof of concept. For more information on Rhizome, see Serval's [documentation](https://github.com/servalproject/serval-dna/blob/development/doc/REST-API-Rhizome.md).

## Overall library design

Clatter is designed as a modular set of Rust libraries (multi-lingual bindings coming soon!), with separate crates available for MDP, MSP, and Rhizome. Clatter is designed to be a thread-safe **asynchronous processing pipeline**. Accordingly, Clatter is designed around the [Futures](https://docs.rs/futures) library. For more information on how Futures work, the homepage for the Futures-based I/O library Tokio [here](https://tokio.rs).

MSP and Rhizome are both built on top of MDP, which contains most of the logic. Clatter's MDP implementation contains most of that logic in a *protocol* object, which is a thread-safe state machine that contains the routing table, message scheduling logic, etc. To that *protocol*, we can bind multiple *sockets* (in this case virtual sockets that are meant to provide an interface similar to UDP sockets, but which transport data over the MDP overlay network) and multiple *interfaces* (the transport over which the MDP message flow, such as traditional UDP/IP). As long as at least one *interface* is bound, MDP will discover other MDP hosts using broadcast messages and form an encrypted overlay network.

When a *socket* is bound, bytes can be sent and received across it much as a standard socket, but behind the scenes those bytes are getting transparently encrypted to their destination key. Clatter's MDP implementation then automatically routes them across whichever interface has the best next-hop connection to get to their final destination.
