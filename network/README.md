## Overview

The network protocol handles discovery, inter-peer communication, and acts as an interface to other modules in the blockchain system. Its primary use during normal case operation is to receive, send, and process consensus messages. It only uses unreliable transport through UDP so the protocol sometimes sends more messages than necessary, specifically during bootup period. The message protocol has been designed with a "good enough" goal in mind and leaves a lot of room for improvements.

## Implementation Details

* **api** is the entry point for other modules in the system to fully use networking
* **client_handle** enables peer discovery and facilitates connection upgrades of peers
* **discovery** finds new peers using mDNS
* **server_handle** handles communication between the backend and other peers
* **message** describes the structure and protocol of peer communication I/O
