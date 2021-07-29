use crate::consensus::transition::Transact;
use crate::ledger::controller::calculate_fee;
use std::collections::HashMap;
use themis::keys::EcdsaPublicKey;

// Replay replays a proposed transition on the ledger to verify its validitiy
pub struct Replay {
    cache: HashMap<u8, Peer>,
}

#[derive(Clone, Debug)]
pub struct Peer(EcdsaPublicKey, /* balance */ u32);

impl Replay {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    #[allow(dead_code)]
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
            let sender_peer = peer_in_record(sender_short_id, tmp.clone());
            if sender_peer.is_err() {
                return Err(sender_peer.err().unwrap());
            }

            // check that the peer can afford the transfer cost (amount + fee)
            let valid_funds = peer_has_funds(sender_short_id, amt, tmp.clone());
            if valid_funds.is_err() {
                return Err(valid_funds.err().unwrap());
            }
            let new_bal = valid_funds.unwrap();
            let sender_pk = sender_peer.unwrap().0;
            let updated_peer = Peer(sender_pk, new_bal);
            tmp.insert(sender_short_id, updated_peer);

            // credit the receiving peer
            let recipient_peer = peer_in_record(recipient_short_id, tmp.clone());
            if recipient_peer.is_err() {
                return Err(recipient_peer.err().unwrap());
            }
            let recipient_peer = recipient_peer.unwrap();
            let updated_recip_peer = Peer(recipient_peer.0.clone(), recipient_peer.1 + amt);
            tmp.insert(recipient_short_id, updated_recip_peer);
        }
        self.update_cache(tmp);
        Ok(())
    }

    #[allow(dead_code)]
    // funds the balance with an amount and returns a Some with the updated peer.
    // If the amount is invalid it returns None.
    fn fund(&mut self, peer_id: u8, amount: u32) -> Result<Peer, std::io::Error> {
        let p = peer_in_record(peer_id, self.cache.clone());
        if p.is_err() {
            return Err(p.err().unwrap());
        }
        let p = p.unwrap();
        let curr_bal = p.1;
        if curr_bal.checked_add(amount).is_some() {
            let new_bal = curr_bal.checked_add(amount).unwrap();
            let peer_updated = Peer(p.0.clone(), new_bal);
            self.cache.insert(peer_id, peer_updated.clone());
            return Ok(peer_updated.clone());
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "amount to incremement invalid",
            ));
        }
    }

    #[allow(dead_code)]
    // defunds the balance with an amount. If the key is not recognized, it inserts
    // a default value of 0 before it subtracts the amount.
    fn defund(&mut self, peer_id: u8, amount: u32) -> Result<Peer, std::io::Error> {
        let p = peer_in_record(peer_id, self.cache.clone());
        if p.is_err() {
            return Err(p.err().unwrap());
        }
        let p = p.unwrap();
        let curr_bal = p.1;
        if curr_bal.checked_sub(amount).is_some() {
            let new_bal = curr_bal.checked_sub(amount).unwrap();
            let peer_updated = Peer(p.0.clone(), new_bal);
            self.cache.insert(peer_id, peer_updated.clone());
            return Ok(peer_updated.clone());
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "amount to decrement invalid",
            ));
        }
    }
}

fn peer_has_funds(id: u8, amount: u32, record: HashMap<u8, Peer>) -> Result<u32, std::io::Error> {
    let peer = peer_in_record(id, record.clone());
    if peer.is_err() {
        return Err(peer.err().unwrap());
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::testcommons::generate_keys;
    use serial_test::serial;
    use tokio_test::{assert_err, assert_ok};

    fn setup(amount_keys: u8) -> Replay {
        let keys = generate_keys(amount_keys);
        let mut rep = Replay::new();
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
        assert_eq!(0, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));
        let res = rep.fund(0, 100);
        assert_ok!(res);
        let res = rep.fund(1, 100);
        assert_ok!(res);
        assert_eq!(100, cache_balance(0, rep.cache()));
        assert_eq!(100, cache_balance(1, rep.cache()));

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
        // End result: balance(A) = 118 and balance(B) = 77
        assert_eq!(118, cache_balance(0, rep.cache()));
        assert_eq!(77, cache_balance(1, rep.cache()));

        let mut txs = vec![];
        for _i in 0..4 {
            txs.push(Transact::new(0, 1, 1));
        }
        let result = rep.run_transition(txs);
        assert_ok!(result);
        assert_eq!(110, cache_balance(0, rep.cache()));
        assert_eq!(81, cache_balance(1, rep.cache()));

        // Send 8 batches of txs of 20 from A to B.
        // Each batch should cost 21 in total so A's balance
        // should not be sufficient which means that we are
        // bailing. No change will occur.
        let mut txs = vec![];
        for _i in 0..8 {
            txs.push(Transact::new(0, 1, 20));
        }
        let result = rep.run_transition(txs);
        assert_err!(result);
        assert_eq!(110, cache_balance(0, rep.cache()));
        assert_eq!(81, cache_balance(1, rep.cache()));

        let res = rep.defund(0, 110);
        assert_ok!(res);
        let res = rep.defund(1, 81);
        assert_ok!(res);
        assert_eq!(0, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));
    }

    #[test]
    #[serial]
    fn run_void_transitions_no_cache_change() {
        let mut rep = setup(2);
        assert_eq!(0, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));

        let res = rep.fund(0, 50);
        assert_ok!(res);
        let tx = vec![Transact::new(0, 1, 50)];
        let result = rep.run_transition(tx);
        assert_err!(result);
        assert_eq!(50, cache_balance(0, rep.cache()));
        assert_eq!(0, cache_balance(1, rep.cache()));
        let res = rep.defund(0, 51);
        assert_err!(res);
        let res = rep.defund(0, 50);
        assert_ok!(res);
        assert_eq!(0, cache_balance(0, rep.cache()));
    }
}
