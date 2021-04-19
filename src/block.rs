use crate::swiss_knife::helper;
use chrono::prelude::*;
use std::fmt::{Display, Formatter};

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug)]
pub struct Block {
    // The identifier of this block
    this_hash: String,
    // The previous block's hash
    previous_hash: String,
    // The time this block was mined
    timestamp: i64,
    // Information of (optional) operations encapsulated in this block
    data: &'static str,
}

impl Block {
    #[allow(dead_code)]
    pub fn new(
        this_hash: String,
        previous_hash: String,
        timestamp: i64,
        data: &'static str,
    ) -> Self {
        Self {
            this_hash,
            previous_hash,
            timestamp,
            data,
        }
    }

    #[allow(dead_code)]
    pub fn genesis(anchor_str: &str) -> Self {
        Self {
            this_hash: helper::generate_hash_from_input(anchor_str),
            previous_hash: "".to_string(),
            timestamp: Utc::now().timestamp_millis(),
            data: "InitBlock",
        }
    }

    pub fn hash(&self) -> &str {
        &self.this_hash
    }

    #[allow(dead_code)]
    pub fn set_hash(&mut self, plain_text: &str) {
        let s = helper::generate_hash_from_input(plain_text);
        // we enable a shared ownership of hash_out ..
        let hash_out = Rc::new(RefCell::new(s));
        // and allow `s` to perform runtime borrow checking ..
        let s = hash_out.clone();
        // final transformation
        let s1 = s.borrow().to_string();
        self.this_hash = s1;
    }

    pub fn set_prev_hash(&mut self, plain_text: &str) {
        let s = helper::generate_hash_from_input(plain_text);
        let hash_out = Rc::new(RefCell::new(s));
        let s = hash_out.clone();
        let s1 = s.borrow().to_string();
        self.previous_hash = s1;
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
        assert_eq!(block.hash(), expected_root_hash);
        assert_eq!(block.previous_hash(), expected_previous_hash);
        assert_eq!(block.data(), expected_block_data);
    }

    #[test]
    fn test_custom_block() {
        let mut block = Block::new(
            hash_out("0x1"),
            hash_out("0x"),
            Utc::now().timestamp_millis(),
            "data1",
        );
        let expected_root_hash = hash_out("0x1");
        let expected_previous_hash = hash_out("0x");
        let expected_block_data = String::from("data1");
        assert_eq!(block.hash(), expected_root_hash);
        assert_eq!(block.previous_hash(), expected_previous_hash);
        assert_eq!(block.data(), expected_block_data);

        // change `current_hash`
        block.set_hash("0xa");
        let expected_new_hash = hash_out("0xa");
        assert_eq!(block.hash(), expected_new_hash);
    }
}
