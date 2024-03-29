#![allow(unused)]
use std::fmt::{Display, Formatter};
use swiss_knife::helper;

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub struct Block {
    // The identifier of this block
    this_hash: String,
    // The previous block's hash
    previous_hash: String,
    // The time this block was mined
    timestamp: i64,
    // Information of (optional) operations encapsulated in this block
    data: &'static str,
    // The place in the chain this block has. The genesis is 0 (first).
    number: u32,
}

impl Block {
    pub fn new(
        this_hash: String,
        previous_hash: String,
        timestamp: i64,
        data: &'static str,
        number: u32,
    ) -> Self {
        Self {
            this_hash,
            previous_hash,
            timestamp,
            data,
            number,
        }
    }

    // genesis creates the first block in the chain which is the only block with
    // no link to a previous block (due to an empty `previous_hash`). It uses the
    // param `init_verifier` to create the first identity anchor of a block as the
    // chain's oldest ancestor.
    pub fn genesis(init_verifier: &'static str) -> Self {
        let tmp = helper::generate_hash_from_input(init_verifier);
        let h = &tmp.clone();
        Self {
            this_hash: h.to_string(),
            previous_hash: "".to_string(),
            timestamp: helper::new_timestamp(),
            data: "The founding block of the blockchain",
            number: 0,
        }
    }

    pub fn hash(&self) -> &str {
        &self.this_hash
    }

    pub fn set_hash(&mut self, plain_text: &'static str) {
        let s = helper::generate_hash_from_input(plain_text);
        // we enable a shared ownership of hash_out ..
        let hash_out = Rc::new(RefCell::new(s));
        // and allow `s` to perform runtime borrow checking ..
        let s = hash_out.clone();
        // final transformation
        let s1 = s.borrow().to_string();
        self.this_hash = s1;
    }

    pub fn set_prev_hash(&mut self, plain_text: String) {
        let s = helper::generate_hash_from_input(&plain_text);
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

    pub fn number(&self) -> u32 {
        self.number
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "<Block info> hash: {}, previous_hash: {}, timestamp: {}, data: {}, number: {}",
            self.hash(),
            self.previous_hash(),
            self.timestamp(),
            self.data(),
            self.number(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swiss_knife::helper::generate_hash_from_input;
    use swiss_knife::hashed; // macros are exported to the crate root level

    #[test]
    fn genesis_block() {
        let block = Block::genesis("0x");
        let expected_root_hash = hashed!("0x");
        let expected_previous_hash = "";
        let expected_block_data = "The founding block of the blockchain";
        assert_eq!(block.hash(), expected_root_hash);
        assert_eq!(block.previous_hash(), expected_previous_hash);
        assert_eq!(block.data(), expected_block_data);
    }

    #[test]
    fn custom_block() {
        let mut block = Block::new(
            hashed!("0x1"),
            hashed!("0x"),
            helper::new_timestamp(),
            "data1",
            0,
        );
        let expected_root_hash = hashed!("0x1");
        let expected_previous_hash = hashed!("0x");
        let expected_block_data = String::from("data1");
        assert_eq!(block.hash(), expected_root_hash);
        assert_eq!(block.previous_hash(), expected_previous_hash);
        assert_eq!(block.data(), expected_block_data);

        // change `current_hash`
        block.set_hash("0xa");
        let expected_new_hash = hashed!("0xa");
        assert_eq!(block.hash(), expected_new_hash);
    }
}
