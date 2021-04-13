use std::fmt::{Display, Formatter};

#[derive(Clone, Debug)]
pub struct Block {
    // The identifier of this block
    hash: &'static str,
    // The previous block's hash
    previous_hash: &'static str,
    // The uuid that solves the hashing algorithm
    nonce: i64,
    // The time this block was mined
    timestamp: u64,
    // Information of (optional) operations encapsulated in this block
    data: &'static str,
}

impl Block {
    #[allow(dead_code)]
    pub fn new(
        hash: &'static str,
        previous_hash: &'static str,
        nonce: i64,
        timestamp: u64,
        data: &'static str,
    ) -> Self {
        Self {
            hash,
            previous_hash,
            nonce,
            timestamp,
            data,
        }
    }

    #[allow(dead_code)]
    pub fn genesis(root_hash: &'static str) -> Self {
        Self {
            hash: root_hash,
            previous_hash: "",
            nonce: 0,
            timestamp: 0,
            data: "",
        }
    }

    pub fn hash(&self) -> &str {
        self.hash
    }

    pub fn previous_hash(&self) -> &'static str {
        self.previous_hash
    }

    pub fn nonce(&self) -> i64 {
        self.nonce
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn data(&self) -> &'static str {
        self.data
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "<Block info> hash: {}, previous_hash: {}, nonce: {}, timestamp: {}, data: {}",
            self.hash(),
            self.previous_hash(),
            self.nonce(),
            self.timestamp(),
            self.data(),
        )
    }
}
