# Abrahm Chain
Abrahm is a permissioned Rust blockchain created for educational purposes. It is inspired by the [go-ethereum](https://github.com/ethereum/go-ethereum) and [diem](https://github.com/diem/diem) clients. A similarity with Ethereum is that it uses the account-based transaction model, mainly for simplicity. Transaction finality is handled through PBFT consensus (Castro and Liskov, 1999). Diem has been used as a reference to better understand designs of Rust blockchains and as an example of how to produce excellent documentation. A significant part of the drive for this project is to implement the PBFT three-phase consensus protocol from its specification and connect it to the other modules of a blockchain system.

Due to the wide scope, building a functional blockchain from scratch, certain trade-offs has been done. The goals have been boiled down to the essentials and the non-goals are many.


### Goal (Implementation features)
* Value ("cryptocurrency") transfer from one entity to another
* Prevent a limited set of attack vectors such double spend and masquerading through cryptography
* Mining mechanism based on a BFT algorithm for relatively high throughput
* Messaging protocol to encapsulate all the stages and states in the blockchain lifecycle
* Concurrent, multithreaded, and asynchronous

### Non-Goals (Omit) and Limitations
* No smart contract functionality or any other functionality apart from send / receive of value
* No additional networking protocols to upgrade and optimize message passing further
* No internetworking support; only supports LAN
* No unbounded amount of peers and scalability; fixed set of validator peers
* No post-startup synchronization; all peers must boot around the same time
* No cross-platform compatibility; only supports macOS

### Architecture
The ambition is to demonstrate the most fundamental components of a working blockchain, albeit with rudimentary functionality. The focus is to deliver a complete and working baseline rather than the most clever, novel, and performant one. The different architectural components are:
* ledger: state database, key management, and chain initialization
* consensus: the state negotiation protocol (PBFT)
* network: peer-to-peer discovery and messaging
* swiss_knife: various helpers
* types: block and transaction types

### Dependencies
The main ones are:
* [themis](https://www.cossacklabs.com/themis/) for encryption and secure message exchange
* [tokio](https://github.com/tokio-rs/tokio) for async and UDP networking
* [libp2p](https://github.com/libp2p/rust-libp2p) for local network discovery (mDNS)
* [rocksdb](https://rocksdb.org/)
