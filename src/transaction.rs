use chrono::prelude::*;
use std::fmt::{Display, Formatter};

#[derive(Copy, Clone)]
struct Label {
    from: &'static str,
    to: &'static str,
    amount: i32,
}

impl Label {
    fn new(from: &'static str, to: &'static str, amount: i32) -> Self {
        Self { from, to, amount }
    }
}

// Transaction is the main P2P transaction between two accounts
#[derive(Copy, Clone)]
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
        from: &'static str,
        to: &'static str,
        amount: i32,
        hash: &'static str,
        expiration_time: u64,
    ) -> Self {
        Self {
            base: Label::new(from, to, amount),
            hash,
            expiration_time,
            first_seen: Utc::now().timestamp_millis(),
        }
    }

    pub fn sender(&self) -> &str {
        return self.base.from;
    }

    pub fn hash(&self) -> &'static str {
        return self.hash;
    }
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "<Transaction> hash: {}, amount: {}, from: {}, to: {}, expiration_time: {}, first_seen: {}",
            self.hash, self.base.amount, self.base.from, self.base.to, self.expiration_time, self.first_seen,
        )
    }
}
