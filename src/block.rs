use crate::swiss_knife::helper;
use chrono::prelude::*;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug)]
pub struct Block {
    // The identifier of this block
    hash: String,
    // The previous block's hash
    previous_hash: String,
    // The time this block was mined
    timestamp: i64,
    // Information of (optional) operations encapsulated in this block
    data: &'static str,
}

impl Block {
    #[allow(dead_code)]
    pub fn new(hash: String, previous_hash: String, timestamp: i64, data: &'static str) -> Self {
        Self {
            hash,
            previous_hash,
            timestamp,
            data,
        }
    }

    #[allow(dead_code)]
    pub fn genesis(anchor_str: &str) -> Self {
        Self {
            hash: helper::generate_hash_from_input(anchor_str),
            previous_hash: "".to_string(),
            timestamp: Utc::now().timestamp_millis(),
            data: "InitBlock",
        }
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    pub fn timestamp(&self) -> i64 {
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
            "<Block info> hash: {}, previous_hash: {}, timestamp: {}, data: {}",
            self.hash(),
            self.previous_hash(),
            self.timestamp(),
            self.data(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swiss_knife::helper;

    fn hash_out(s: &str) -> String {
        helper::generate_hash_from_input(s)
    }

    #[test]
    fn test_genesis_block() {
        let block = Block::genesis("0x");
        let expected_root_hash = hash_out("0x");
        let expected_previous_hash = "";
        let expected_block_data = "InitBlock";
        assert_eq!(block.hash, expected_root_hash);
        assert_eq!(block.previous_hash, expected_previous_hash);
        assert_eq!(block.data, expected_block_data);
    }

    #[test]
    fn test_custom_block() {
        let block = Block::new(
            hash_out("0x1"),
            hash_out("0x"),
            Utc::now().timestamp_millis(),
            "data1",
        );
        let expected_root_hash = hash_out("0x1");
        let expected_previous_hash = hash_out("0x");
        let expected_block_data = String::from("data1");
        assert_eq!(block.hash, expected_root_hash);
        assert_eq!(block.previous_hash, expected_previous_hash);
        assert_eq!(block.data, expected_block_data);
    }
}
