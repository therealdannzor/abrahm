use std::fmt::{Display, Formatter}

struct Block {
    // The identifier of this block
    hash: String,
    // The previous block's hash
    previous_hash: String,
    // The uuid that solves the hashing algorithm 
    nonce: i64,
    // The time this block was mined
    timestamp: u64, 
    // Information of (optional) operations encapsulated in this block
    data: Option<String>,
}

impl Block {
    pub fn new(
        hash: String,
        previous_hash: String,
        nonce: i64,
        timestamp: u64,
        data: Option<String>,
    ) -> Self {
        Self {
            hash,
            previous_hash,
            nonce, 
            timestamp, 
            data,
        }
    }

    pub fn genesis(root_hash String) -> Self {
        Self {
            hash: root_hash,
            previous_hash: "".to_string(),
            nonce: 0,
            timestamp: 0,
            data: "".to_string(),
        }
    }

    pub fn hash(&self) -> String {
        self.hash
    }

    pub fn previous_hash(&self) -> String {
        self.previous_hash
    }

    pub fn nonce(&self) -> i64 {
        self.nonce
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn data(&self) -> Option(String) {
        // returns `None` if data `self.data` is None
        let dat: String = self.data?;
        // else returns the data
        Some(dat)
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f, "<Block info> hash: {}, previous_hash: {}, nonce: {}, timestamp: {}, data: {}",
            self.hash(), self.previous_hash(), self.nonce(), self.timestamp(), self.data(),
        )
    }
}
