#![allow(unused)]

use crate::consensus::transition::{Transact, Transition};
use crate::ledger::controller::{calculate_fee, LedgerStateController};
use std::collections::HashMap;
use themis::keys::EcdsaPublicKey;

// Replay replays a proposed transition on the ledger to verify its validitiy
pub struct Replay {
    cache: HashMap<u8, Peer>,
    last_state_hash: String,
}
struct Peer(EcdsaPublicKey, /* balance */ u32);

impl Replay {
    pub fn new(last_state_hash: String) -> Self {
        Self {
            cache: HashMap::new(),
            last_state_hash,
        }
    }

    // run_transition simulates a list of transactions on the local cache. It is assumed that the
    // cache is up-to-date with the state database.
    pub fn run_transition(&mut self, txs: Vec<Transact>) -> Result<(), std::io::Error> {
        let mut balances = HashMap::<EcdsaPublicKey, u32>::new();
        for it in txs.clone().iter() {
            let sender_short_id = it.from();
            let recipient_short_id = it.to();
            let amt = it.amount();

            // subtract from the sending peer
            let sender_peer = self.cache.get(&sender_short_id);
            if sender_peer.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing public key",
                ));
            }
            let sender_pk = sender_peer.unwrap().0.clone();
            let sender_bal = self.cache_balance(sender_short_id);
            let fee = calculate_fee(amt as u16) as u32;
            if sender_bal < amt + fee {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not enough funds to make transfer",
                ));
            }
            let new_bal = sender_bal - amt - fee;
            let updated_peer = Peer(sender_pk, new_bal);
            self.cache.insert(sender_short_id, updated_peer);

            // credit the receiving peer
            let recipient_peer = self.cache.get(&recipient_short_id);
            if recipient_peer.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "target peer short code not found",
                ));
            }
            let recipient_pk = &recipient_peer.unwrap().0;
            let recipient_bal = self.cache_balance(recipient_short_id);
            let new_bal = recipient_bal + amt;
            let updated_peer = Peer(recipient_pk.clone(), new_bal);
            self.cache.insert(recipient_short_id, updated_peer);
        }
        Ok(())
    }

    fn cache_balance(&self, account: u8) -> u32 {
        let p = self.cache.get(&account);
        if p.is_none() {
            return 0;
        } else {
            return p.unwrap().1;
        }
    }

    // increments the balance with an amount and returns a Some of the new amount.
    // If the key is not recognized, it returns None.
    fn inc_balance(&mut self, account: u8, amount: u32) -> Option<u32> {
        let curr_bal = self.cache_balance(account);
        let peer = self.cache.get(&account);
        if peer.is_none() {
            return None;
        } else if curr_bal.checked_add(amount).is_some() {
            let peer = peer.unwrap();
            let new_bal = curr_bal.checked_add(amount).unwrap();
            let peer_updated = Peer(peer.0.clone(), new_bal);
            self.cache.insert(account, peer_updated);
            return Some(new_bal);
        } else {
            return None;
        }
    }

    // decrements the balance with an amount. If the key is not recognized, it inserts
    // a default value of 0 before it subtracts the amount.
    fn dec_balance(&mut self, account: u8, amount: u32) -> Option<u32> {
        let curr_bal = self.cache_balance(account);
        let peer = self.cache.get(&account);
        if peer.is_none() {
            return None;
        } else if curr_bal.checked_sub(amount).is_some() {
            let peer = peer.unwrap();
            let new_bal = curr_bal.checked_sub(amount).unwrap();
            let peer_updated = Peer(peer.0.clone(), new_bal);
            self.cache.insert(account, peer_updated);
            return Some(new_bal);
        } else {
            return None;
        }
    }

    fn update_state_hash(mut self, hash: String) {
        self.last_state_hash = hash;
    }
}

mod tests {
    use super::*;
    use crate::consensus::{testcommons::generate_keys, transition::Transact};
    use serial_test::serial;
    use tokio_test::{assert_err, assert_ok};

    fn setup(amount_keys: u8) -> Replay {
        let keys = generate_keys(amount_keys);
        let mut rep = Replay::new(String::from("0x"));
        for i in 0..keys.len() {
            let p = Peer(keys[i].clone(), 0);
            rep.cache.insert(i as u8, p);
        }
        rep
    }

    #[test]
    #[serial]
    fn run_happy_transitions_and_cache_correctly() {
        // scenario setup
        let mut rep = setup(2);
        rep.inc_balance(0, 50);
        rep.inc_balance(1, 50);

        // Create proposed transitions:
        let txs = vec![
            Transact::new(0 /* A */, 1 /* B */, 40), // Send 40 from A to B
            Transact::new(1 /* B */, 0 /* A */, 60), // Send 60 from B to A
        ];
        let result = rep.run_transition(txs);
        assert_ok!(result);

        // The fee to transfer is:
        // For A: ceil(0.05 x 40) = 2
        // For B: ceil(0.05 x 60) = 3
        // End result: balance(A) = 68 and balance(B) = 27
        assert_eq!(68, rep.cache_balance(0));
        assert_eq!(27, rep.cache_balance(1));

        let mut txs = vec![];
        for i in 0..4 {
            txs.push(Transact::new(0, 1, 1));
        }
        let result = rep.run_transition(txs);
        assert_ok!(result);
        assert_eq!(60, rep.cache_balance(0));
        assert_eq!(31, rep.cache_balance(1));

        // Send 8 batches of txs of 9 from A to B.
        // Each batch should cost 1 (10 in total) so A's balance
        // should be completely empty after only 6, leaving 2 of
        // them as invalid.
        let mut txs = vec![];
        for i in 0..8 {
            txs.push(Transact::new(0, 1, 9));
        }
        let result = rep.run_transition(txs);
        assert_err!(result);
        assert_eq!(0, rep.cache_balance(0));
        assert_eq!(85, rep.cache_balance(1));
    }

    #[test]
    #[serial]
    fn run_void_transitions_no_cache_change() {
        let mut rep = setup(2);
        assert_eq!(0, rep.cache_balance(0));
        assert_eq!(0, rep.cache_balance(1));

        rep.inc_balance(0, 50);
        let tx = vec![Transact::new(0, 1, 50)];
        let result = rep.run_transition(tx);
        assert_err!(result);
        assert_eq!(50, rep.cache_balance(0));
        assert_eq!(0, rep.cache_balance(1));
    }
}
