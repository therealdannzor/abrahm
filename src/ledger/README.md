## Overview

The ledger contains the state of the blockchain and other constructs to manage the ledger. These constructs are either part of the initialisation process (such as the bootstrap and keystore) or coupled with the state databse to execute transactions. We would expect that the state of the blockchain, identified by the root hash, is same for all participants. The negotiation process to assure that every peer has the same truth (i.e., state database) is handled by the consensus system.

## Implementation Details

* **state_db** is the core implementation of the blockchain state, stored in a key-value database. It supports basic CRUD functionality and updates the root hash at every change.
* **replay** takes a proposed set of transition and does a dry run to see if it is valid on the ledger
* **keystore** creates and manages key files that contains a public and private key pair.
* **bootstrap** loads configuration and key files into the blockchain system
* **controller** alters the state database through fund and transfer operations
