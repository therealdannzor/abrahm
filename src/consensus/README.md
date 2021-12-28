## Overview

The consensus protocol is part of the blockchain _mining_ mechanism, confirming the validity of proposed transactions (as referenced by its own state database) among a set of potentially untrusted agents on a network. If the amount of faulty (hostile) agents have a lower bound, here 1/3 of the total amount of participants, the protocol has mechanisms in place to assure _safety_ and _liveness_. This is the lower bound and the definition of the concepts can be found in Section 4.5 Correctness [here](https://www.pmg.csail.mit.edu/papers/osdi99.pdf).

## Implementation Details

* **engine** is the core abstraction of the consensus protocol, containing the lower-level abstractions. It has the implemented PBFT protocol specification.
* **leader_process** assigns and manages the primary (leader) of a unique consensus round
* **state** codifies the state of a consensus message as a value between 0 and 6 (inclusive) in a custom message type
* **transition** checks whether a set of transactions are valid according to current state and that the state transition is possible
* **view** is the implemented view-change protocol to provide liveness to allow the system to continue if (when) the leader fails
* **common** contains some consensus types and helper functions used frequently
