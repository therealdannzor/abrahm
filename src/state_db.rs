use std::path::Path;
use std::vec::Vec;

extern crate leveldb;
use leveldb::options::{Options, WriteOptions, ReadOptions};
use leveldb::database::Database;
use leveldb::database::batch::{Batch, Writebatch};
use leveldb::kv::KV;

extern crate crypto;
use self::crypto::sha2::Sha256;
use self::crypto::digest::Digest;


pub trait KeyValueIO {
    // new creates a new key-value reader-writer
    fn new(path: &str) -> StateDB;

    // put inserts the key-value pair in the data storage
    fn put(&mut self, key: i32, value: &[u8]);

    // delete removes the key from the data storage
    fn delete(&mut self, key: i32);


    // get_value retrieves the value of the key if it exists. If it is does not
    // it returns a dummy ouput of 0.
    fn get_value(&self, key: i32) -> Vec<u8>;

    // update_root_hash receives a key-value pair and creates a hash
    // based on the existing root hash and this pair to represent a
    // simple and traceable transition of state change
    fn update_root_hash(&mut self, key: i32, val: &[u8]);

    // get_root_hash retrieves the root hash of the state db which represents
    // the freshest and latest change to the db
    fn get_root_hash(&self) -> String;
}

pub struct StateDB {
    // The leveldb database
    db: Database<i32>,

    // The hash of all the states. Each state consists of a key-value pair
    // which represents the account and its balance.
    root_hash: String
}

impl KeyValueIO for StateDB {
    fn new(path: &str) -> StateDB {
        let mut opts = Options::new();
        opts.create_if_missing = true;
        let path_format = Path::new(&path);
        let database = Database::open(path_format, opts).unwrap();

        let mut hasher = Sha256::new();
        hasher.input(b"AbrahmChain");
        let hash_out = hasher.result_str();

        StateDB { db: database, root_hash: hash_out }
    }

    fn put(&mut self, key: i32, val: &[u8]) {
        let res = write_db(&self.db, key, val);
        match res {
            Ok(_) => self.update_root_hash(key, val),
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn delete(&mut self, key: i32) {
        let res = get_db(&self.db, key);
        // if the value is empty we don't need to send a delete cmd
        // since there is no balance-relevant state to change
        if res == &[0] {
            return
        }

        let ack = del_db(&self.db, key);
        match ack {
            Ok(_) => {
                let empty = vec![0];
                self.update_root_hash(key, &empty);
            },
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn get_value(&self, key: i32) -> Vec<u8> {
        get_db(&self.db, key)
    }

    fn update_root_hash(&mut self, key: i32, val: &[u8]) {
        let mut input = self.root_hash.clone();
        input.push_str(&key.to_string());
        let val_str: String = val.into_iter().map(|i| i.to_string()).collect::<String>();
        input.push_str(&val_str);
        let mut new_hash = Sha256::new();
        new_hash.input_str(&input);

        self.root_hash = new_hash.result_str()
    }

    fn get_root_hash(&self) -> String {
        self.root_hash.clone()
    }
}

fn get_db(db: &Database<i32>, key: i32) -> Vec<u8> {
    let read_opts = ReadOptions::new();
    let query_result = db.get(read_opts, key);
    match query_result {
        Ok(data) => {
            // if entry does not exist, return a dummy output of [0]
            data.unwrap_or(vec!(0))
        },
        Err(e) => panic!("read db error: {:?}", e),
    }
}

fn write_db(db: &Database<i32>, key: i32, val: &[u8]) -> Result<(), leveldb::error::Error> {
    let batch = &mut Writebatch::new();
    batch.put(key, val);
    let write_opts = WriteOptions::new();
    let ack = db.write(write_opts, batch);
    ack
}

fn del_db(db: &Database<i32>, key: i32) -> Result<(), leveldb::error::Error> {
   let batch = &mut Writebatch::new();
   batch.delete(key);
   let write_opts = WriteOptions::new();
   let ack = db.write(write_opts, batch);
   ack
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_new_insert_expect_new_state_change() {
        let mut db = setup();
        let root = db.get_root_hash();

        // fund account `1` with a balance
        db.put(1, &[2]);
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(1), &[2]);
        let root = new_root;

        db.put(2, &[3]);
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(2), &[3]);

        db.delete(1);
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(1), &[0]);
        let root = new_root;

        db.delete(9); // does not exist
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);

    }

    #[test]
    #[serial]
    fn test_new_insert_and_delete_expect_new_state() {
        let mut db = setup();
        let root = db.get_root_hash();

        db.put(1, &[2]);
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(1), &[2]);
        let root = new_root;

        // remove all non-nil balance from account `1`
        db.delete(1);
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(1), &[0]);

    }

    #[test]
    #[serial]
    fn test_delete_missing_key_expect_no_state_change() {
        let mut db = setup();

        db.put(1, &[2]);
        let root = db.get_root_hash();
        // send a delete cmd to a key which is missing
        db.delete(5);
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);
    }

    #[test]
    #[serial]
    fn test_delete_key_with_no_balance_expect_no_state_change() {
        let mut db = setup();

        db.put(1, &[0]);
        let root = db.get_root_hash();
        // send delete cmd to a key which has no balance
        db.delete(1);
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);
    }

    fn setup() -> StateDB {
        let mut tmp_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        tmp_path.push_str("/test");
        let dir = TempDir::new(&tmp_path);
        match dir {
            Ok(_) => (),
            Err(e) => panic!("could not create tmp dir: {:?}", e),
        }
        println!("path: {:?}", dir);

        let db = StateDB::new(&tmp_path);
        db
    }

}
