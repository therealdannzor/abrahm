#![allow(unused)]

use crate::consensus::transition::{Transact, Transition};
use crate::ledger::controller::{calculate_fee, LedgerStateController};
use std::collections::HashMap;
use themis::keys::EcdsaPublicKey;

// Replay replays a proposed transition on the ledger to verify its validitiy
pub struct Replay {
    cache: HashMap<EcdsaPublicKey, u32>,
    last_state_hash: String,
}
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
            let from = it.from();
            let to = it.to();
            let amt = it.amount();
            let from_pk = EcdsaPublicKey::try_from_slice(&from);
            if from_pk.is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    from_pk.err().unwrap().to_string(),
                ));
            }
            let from_pk = from_pk.unwrap();
            let from_bal = self.cache_balance(from_pk.clone());
            let fee = calculate_fee(amt as u16) as u32;
            if from_bal < amt + fee {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not enough funds to make transfer",
                ));
            }
            let new_bal = from_bal - amt - fee;
            self.cache.insert(from_pk, new_bal);
            let to_pk = EcdsaPublicKey::try_from_slice(&to);
            if to_pk.is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    to_pk.err().unwrap().to_string(),
                ));
            }
            let to_pk = to_pk.unwrap();
            let to_bal = self.cache_balance(to_pk.clone());
            let new_bal = to_bal + amt;
            self.cache.insert(to_pk, new_bal);
        }
        Ok(())
    }

    fn cache_balance(&self, account: EcdsaPublicKey) -> u32 {
        *self.cache.get(&account).or(Some(&0)).unwrap()
    }

    // incrememts the balance with an amount. If the key is not recognized, it inserts
    // a default value of 0 before it adds the amount.
    fn inc_balance(&mut self, account: EcdsaPublicKey, amount: u32) -> u32 {
        *self.cache.entry(account.clone()).or_insert(0) += amount;
        *self.cache.get(&account).unwrap()
    }

    // decrements the balance with an amount. If the key is not recognized, it inserts
    // a default value of 0 before it subtracts the amount.
    fn dec_balance(&mut self, account: EcdsaPublicKey, amount: u32) -> u32 {
        let curr_bal = self.cache.get(&account.clone());
        if curr_bal.is_none() {
            self.cache.insert(account.clone(), 0);
            return 0;
            // this shouldn't really happen due to other checks
        } else if curr_bal.unwrap() < &amount {
            self.cache.insert(account.clone(), 0);
            return 0;
        } else {
            let delta = curr_bal.unwrap() - amount;
            self.cache.insert(account, delta);
            return delta;
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
    use tokio_test::assert_ok;

    fn setup(key: EcdsaPublicKey) -> Replay {
        let keys = generate_keys(1);
        let rep = Replay::new(String::from("0x"));
        rep
    }

    #[test]
    #[serial]
    fn run_happy_transitions_and_cache_correctly() {
        // scenario setup
        let keys = &generate_keys(2);
        let alice_pk = &keys[0];
        let bob_pk = &keys[1];
        let mut rep = setup(alice_pk.clone());
        rep.inc_balance(alice_pk.clone(), 50);
        rep.inc_balance(bob_pk.clone(), 50);

        // Create proposed transitions:          send 40 from A to B and 60 from B to A.
        // The fee to transfer is:               0.05 x 40 = 2
        // After which the end result should be: balance(A) = 68 and balance(B) = 30
        let txs = vec![
            Transact::new(alice_pk.clone(), bob_pk.clone(), 30),
            Transact::new(bob_pk.clone(), alice_pk.clone(), 50),
        ];

        let result = rep.run_transition(txs);
        assert_ok!(result);
    }
}
