use std::fmt::{Display, Formatter};

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

pub struct Transaction {
    base: Label,
    data: &'static str,
    hash: &'static str,
    expiration_time: u64,
}

impl Transaction {
    #[allow(dead_code)]
    pub fn new(
        from: &'static str,
        to: &'static str,
        amount: i32,
        data: &'static str,
        hash: &'static str,
        expiration_time: u64,
    ) -> Self {
        Self {
            base: Label::new(from, to, amount),
            data,
            hash,
            expiration_time,
        }
    }
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "<Transaction> hash: {}, amount: {}, from: {}, to: {}, data: {}, expiration_time: {}",
            self.hash,
            self.base.amount,
            self.base.from,
            self.base.to,
            self.data,
            self.expiration_time,
        )
    }
}
