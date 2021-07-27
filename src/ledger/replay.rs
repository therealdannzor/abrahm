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

#[derive(Clone)]
pub struct Peer(EcdsaPublicKey, /* balance */ u32);

impl Replay {
    pub fn new(last_state_hash: String) -> Self {
        Self {
            cache: HashMap::new(),
            last_state_hash,
        }
    }

    pub fn cache(&self) -> HashMap<u8, Peer> {
        self.cache.clone()
    }

    fn update_cache(&mut self, c: HashMap<u8, Peer>) {
        self.cache = c;
    }

    // run_transition simulates a list of transactions on the local cache. It is assumed that the
    // cache is up-to-date with the state database.
    pub fn run_transition(&mut self, txs: Vec<Transact>) -> Result<(), std::io::Error> {
        let sufficient = atleast_one_tx(txs.clone());
        if sufficient.is_err() {
            return Err(sufficient.err().unwrap());
        }

        let mut tmp = self.cache.clone();
        for it in txs.clone().iter() {
            let sender_short_id = it.from();
            let recipient_short_id = it.to();
            let amt = it.amount();

            // check that we have seen this peer before
            let sender_peer = peer_in_record(sender_short_id, self.cache.clone());
            if sender_peer.is_err() {
                return Err(sender_peer.err().unwrap());
            }

            // check that the peer can afford the transfer cost (amount + fee)
            let valid_funds = peer_has_funds(sender_short_id, amt, self.cache.clone());
            if valid_funds.is_err() {
                return Err(valid_funds.err().unwrap());
            }
            let new_bal = valid_funds.unwrap();
            let sender_pk = sender_peer.unwrap().0;
            let updated_peer = Peer(sender_pk, new_bal);
            tmp.insert(sender_short_id, updated_peer);

            // credit the receiving peer
            let recipient_peer = peer_in_record(recipient_short_id, self.cache.clone());
            if recipient_peer.is_err() {
                return Err(recipient_peer.err().unwrap());
            }
            let recipient_peer = recipient_peer.unwrap();
            let updated_recip_peer =
                self.inc_balance(recipient_peer.clone(), recipient_peer.1 + amt);
            if updated_recip_peer.is_err() {
                return Err(updated_recip_peer.err().unwrap());
            }
            let updated_recip_peer = updated_recip_peer.unwrap();
            tmp.insert(recipient_short_id, updated_recip_peer);
        }
        self.update_cache(tmp);
        Ok(())
    }

    // increments the balance with an amount and returns a Some with the updated peer.
    // If the amount is invalid it returns None.
    fn inc_balance(&mut self, peer: Peer, amount: u32) -> Result<Peer, std::io::Error> {
        let curr_bal = peer.1;
        if curr_bal.checked_add(amount).is_some() {
            let new_bal = curr_bal.checked_add(amount).unwrap();
            let peer_updated = Peer(peer.0.clone(), new_bal);
            return Ok(peer_updated.clone());
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "amount to incremement invalid",
            ));
        }
    }

    // decrements the balance with an amount. If the key is not recognized, it inserts
    // a default value of 0 before it subtracts the amount.
    fn dec_balance(&mut self, account: u8, amount: u32) -> Option<u32> {
        let curr_bal = cache_balance(account, self.cache.clone());
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

fn peer_has_funds(id: u8, amount: u32, record: HashMap<u8, Peer>) -> Result<u32, std::io::Error> {
    let peer = peer_in_record(id, record.clone());
    if peer.is_err() {
        return Err(peer.err().unwrap());
    }
    let pk = peer.unwrap().0.clone();
    let bal = cache_balance(id, record.clone());
    let fee = calculate_fee(amount as u16) as u32;
    if bal < amount as u32 + fee {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not enough funds to transfer",
        ));
    }
    let new_bal = bal - fee - amount;
    Ok(new_bal)
}

fn peer_in_record(id: u8, record: HashMap<u8, Peer>) -> Result<Peer, std::io::Error> {
    let peer = record.get(&id);
    if peer.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing public key",
        ));
    }
    Ok(peer.unwrap().clone())
}

fn atleast_one_tx(vec: Vec<Transact>) -> Result<(), std::io::Error> {
    if vec.len() < 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no transaction to process",
        ));
    }
    Ok(())
}

fn cache_balance(account: u8, cache: HashMap<u8, Peer>) -> u32 {
    let p = cache.get(&account);
    if p.is_none() {
        return 0;
    } else {
        return p.unwrap().1;
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
        inc_balance(0, 50, rep.cache());
        inc_balance(1, 50, rep.cache());

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
        assert_eq!(68, cache_balance(0, rep.cache()));
        assert_eq!(27, cache_balance(1, rep.cache()));

        let mut txs = vec![];
        for i in 0..4 {
            txs.push(Transact::new(0, 1, 1));
        }
        let result = rep.run_transition(txs);
        assert_ok!(result);
        assert_eq!(60, cache_balance(0, rep.cache()));
        assert_eq!(31, cache_balance(1, rep.cache()));

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
        assert_eq!(0, cache_balance(0, rep.cache()));
        assert_eq!(85, cache_balance(1, rep.cache()));
    }

    #[test]
    #[serial]
    fn run_void_transitions_no_cache_change() {
        let mut rep = setup(2);
        assert_eq!(0, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));

        inc_balance(0, 50, rep.cache());
        let tx = vec![Transact::new(0, 1, 50)];
        let result = rep.run_transition(tx);
        assert_err!(result);
        assert_eq!(50, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));
    }
}
