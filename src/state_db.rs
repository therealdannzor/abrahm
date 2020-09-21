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
    fn new() -> StateDB;

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
    fn new() -> StateDB {
        let mut db_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        db_path.push_str("/leveldb");
        let mut opts = Options::new();
        opts.create_if_missing = true;
        let path_format = Path::new(&db_path);
        let database = Database::open(path_format, opts).unwrap();

        let mut hasher = Sha256::new();
        hasher.input(b"AbrahmChain");
        let hash_out = hasher.result_str();

        StateDB { db: database, root_hash: hash_out }
    }

    fn put(&mut self, key: i32, val: &[u8]) {
        let batch = &mut Writebatch::new();
        batch.put(key, val);
        let write_opts = WriteOptions::new();
        let ack = self.db.write(write_opts, batch);
        match ack {
            Ok(_) => {
                self.update_root_hash(key, val);
            },
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn delete(&mut self, key: i32) {
        let batch = &mut Writebatch::new();
        batch.delete(key);
        let write_opts = WriteOptions::new();
        let ack = self.db.write(write_opts, batch);
        match ack {
            Ok(_) => {
                let empty = vec![0];
                self.update_root_hash(key, &empty);
            }, 
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn get_value(&self, key: i32) -> Vec<u8> {
        let read_opts = ReadOptions::new();
        let query_result = self.db.get(read_opts, key);
        match query_result {
            Ok(data) => {
            // if entry does not exist, return a dummy output of [0]
            data.unwrap_or(vec!(0))
            },
            Err(e) => panic!("read db error: {:?}", e),
        }
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

