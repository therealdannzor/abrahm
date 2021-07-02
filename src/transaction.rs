use crate::swiss_knife::helper;
use std::fmt::{Display, Formatter};
use themis::keys::EcdsaPublicKey;

#[derive(Clone)]
struct Label {
    from: EcdsaPublicKey,
    to: EcdsaPublicKey,
    amount: i32,
}

impl Label {
    fn new(from: EcdsaPublicKey, to: EcdsaPublicKey, amount: i32) -> Self {
        Self { from, to, amount }
    }
}

// Transaction is the main P2P transaction between two accounts
#[derive(Clone)]
pub struct Transaction {
    // main payload of a transaction
    base: Label,
    // transaction hash
    hash: &'static str,
    // transaction TTL
    expiration_time: u64,
    // local anti-spam mechanism
    first_seen: i64,
}

impl Transaction {
    #[allow(dead_code)]
    pub fn new(
        from: EcdsaPublicKey,
        to: EcdsaPublicKey,
        amount: i32,
        hash: &'static str,
        expiration_time: u64,
    ) -> Self {
        Self {
            base: Label::new(from, to, amount),
            hash,
            expiration_time,
            first_seen: helper::new_timestamp(),
        }
    }

    pub fn sender(&self) -> EcdsaPublicKey {
        self.base.from.clone()
    }

    pub fn receiver(&self) -> EcdsaPublicKey {
        self.base.to.clone()
    }

    pub fn hash(&self) -> &'static str {
        return self.hash;
    }
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "<Transaction> hash: {}, amount: {}, from: {:?}, to: {:?}, expiration_time: {}, first_seen: {}",
            self.hash, self.base.amount, self.sender().as_ref(), self.receiver().as_ref(), self.expiration_time, self.first_seen,
        )
    }
}
