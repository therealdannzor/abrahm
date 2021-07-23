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

    pub fn run_transition(
        &mut self,
        controller: LedgerStateController,
        txs: Vec<Transact>,
    ) -> Result<(), std::io::Error> {
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
            let from_bal = controller.balance(from_pk.clone());
            let fee = calculate_fee(amt as u16) as u32;
            if from_bal < amt + fee {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not enough funds to make transfer",
                ));
            }
            self.cache.insert(from_pk, from_bal);
            let to_pk = EcdsaPublicKey::try_from_slice(&to);
            if to_pk.is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    to_pk.err().unwrap().to_string(),
                ));
            }
            let to_pk = to_pk.unwrap();
            let to_bal = controller.balance(to_pk.clone());
            self.cache.insert(to_pk, to_bal);
        }
        Ok(())
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
