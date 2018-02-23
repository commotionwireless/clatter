# Clatter
#### NOTE: THIS IS AN EARLY VERSION PENDING A SECURITY AUDIT. THERE ARE BUGS, AND THE API IS SUBJECT TO CHANGE. IT IS NOT YET FULLY COMPATIBLE WITH SERVAL BUT WILL BE SOON.
Clatter is a set of software libraries for secure, device-to-device communication without using the internet. The purpose of the Clatter project is to create memory-safe implementations of offline networking protocols with clear APIs and documentation to make it easy for developers to add these technologies to their applications. Currently, Clatter includes implementations of three protocols pioneered by the [Serval Project](https://servalproject.org). Features listed below include those either already planned or in existence for Serval, and their implementation status in Clatter.

## Contents

### **Mesh Datagram Protocol (MDP)**
MDP is an encrypted network protocol addressed by curve22519 public keys instead of IP addresses. It is conceptually independent of IP but is currently utilized primarily un top of UDP/IP. It provides message confidentiality, has built-in mesh routing, and is highly optimized for low-bandwidth wireless broadcast networks.

#### Features
- [x] Message confidentiality
- [x] Mesh routing
- [x] Per-hop retransmission
- [ ] STUN/TURN (for unicast support)
- [ ] Compression

#### Documentation
[API](https://docs.rs/mdp) | [Architecture](https://github.com/commotionwireless/clatter/blob/master/doc/Architecture.md#MDP) | [Serval](https://github.com/servalproject/serval-dna/blob/development/doc/Mesh-Datagram-Protocol.md)

#### Usage
First, add this to your `Cargo.toml`:
```toml
[dependencies]
mdp = "0.1.0"
```

Next, add this to your crate:

```rust
extern crate mdp;
```
See the [here](https://docs.rs/mdp) for documentation and examples.

### **Mesh Streaming Protocol (MSP)**
MSP is an encrypted network streaming protocol built on top of MDP. Whereas MDP is analagous to UDP, MSP is analagous to TCP. MSP provides session handling, in-order transmission of messages, and reliable rebroadcast.

#### Features (in addition to MDP's)
- [x] Session handling
- [x] In-order message delivery
- [x] Reliable transmission
- [ ] Perfect forward secrecy

#### Documentation
[API](https://docs.rs/rhizome) | [Architecture](https://github.com/commotionwireless/clatter/blob/master/doc/Architecture.md#MSP) | [Serval](https://github.com/servalproject/serval-dna/blob/development/doc/REST-API-Rhizome.md)

#### Usage
First, add this to your `Cargo.toml`:
```toml
[dependencies]
msp = "0.1.0"
```

Next, add this to your crate:

```rust
extern crate msp;
```
See the [here](https://docs.rs/msp) for documentation and examples.

### **Rhizome (COMING SOON)**
Rhizome is a delay-tolerant-messaging (DTN) layer on top of the Serval protocol stack. Rhizome transmits message "bundles" that are best-effort synchronized across all nodes in the network. Rhizome provides a decentraized method of transmitting files and messages within a network that is unreliable or sparsely connected.

#### Features (in addition to MDP's)
- [x] Delay tolerance
- [x] Bundle confidentiality
- [x] Bundle pseudonymity
- [ ] Append-only encrypted journaling
- [ ] SMS-like messaging service
- [ ] Tree-based synchronization protocol

#### Documentation
[API](https://docs.rs/msp) | [Architecture](https://github.com/commotionwireless/clatter/blob/master/doc/Architecture.md#MSP) | [Serval](https://github.com/servalproject/serval-dna/blob/development/doc/Mesh-Stream-Protocol.md)

#### Usage
First, add this to your `Cargo.toml`:
```toml
[dependencies]
rhizome = "0.1.0"
```

Next, add this to your crate:

```rust
extern crate rhizome;
```
See the [here](https://docs.rs/rhizome) for documentation and examples.

## License
[<img src="https://www.gnu.org/graphics/gplv3-127x51.png" alt="GPLv3" >](http://www.gnu.org/licenses/gpl-3.0.html)

Clatter is a free software project licensed under the GNU General Public License v3.0 (GPLv3). It implements open protocols designed by the [Serval Project](http://servalproject.org).
