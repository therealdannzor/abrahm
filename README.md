# Abrahm Chain
Abrahm is a Rust blockchain created for educational purposes. It is inspired by the [go-ethereum](https://github.com/ethereum/go-ethereum) and [diem](https://github.com/diem/diem) clients. A similarity with Ethereum is that it uses the account-based transaction model, mainly for simplicity. Transaction finality is done through PBFT consensus (Castro and Liskov, 1999). Diem has been used as a reference to better understand designs of Rust blockchains and as an example of how you produce excellent documentation. A significant part of the drive for this project is to implement the PBFT three-phase consensus protocol from its specification and connect it to the other modules of a blockchain system.

Due to the wide scope, building a functional blockchain from scratch, certain trade-offs has been done. The goals have been boiled down to the essentials and the non-goals are many.

### Goal (Implementation features)
* Value ("cryptocurrency") transfer from one entity to another
* Prevent a limited set of attack vectors such double spend and masquerading through cryptography
* Mining mechanism based on a BFT protocol for relatively high throughput
* Messaging protocol to encapsulate all the stages and states in the blockchain lifecycle
* Concurrent, multithreaded, and asynchronous

### Design
The ambition is to demonstrate the most fundamental components of a working blockchain, albeit with rudimentary functionality. The focus is to deliver a complete and working baseline rather than the most clever, novel, and performant one.

### Dependencies
The main ones are:
* [themis](https://www.cossacklabs.com/themis/) for encryption and secure message exchange
* [tokio](https://github.com/tokio-rs/tokio) for async and UDP networking
* [rocksdb](https://rocksdb.org/)
