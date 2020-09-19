use std::path::Path;
use std::result::Result;
use std::vec::Vec;
use std::io::Error;

extern crate leveldb;

use leveldb::options::{Options, WriteOptions, ReadOptions};
use leveldb::database::Database;
use leveldb::database::batch::{Batch, Writebatch};
use leveldb::kv::KV;


pub trait KeyValueIO {
    // new creates a new key-value reader-writer
    fn new() -> Self;

    // put inserts the key-value pair in the data storage
    fn put(&self, key: i32, value: &[u8]) -> Result<(), Error>;

    // delete removes the key from the data storage
    fn delete(&self, key: i32) -> Result<(), Error>;

    // del retrieves the value of the key if it exists
    fn get(&self, key: i32) -> Vec<u8>;
}

pub struct StateDB {
    // The leveldb database
    db: Database<i32>,
}

impl KeyValueIO for StateDB {
    fn new() -> Self {
        let mut db_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        db_path.push_str("/leveldb");
        let mut opts = Options::new();
        opts.create_if_missing = true;
        let path_format = Path::new(&db_path);
        let database = Database::open(path_format, opts).unwrap();

        Self { db: database }
    }

    fn put(&self, key: i32, val: &[u8]) -> Result<(), Error> {
        let batch = &mut Writebatch::new();
        batch.put(key, val);
        let write_opts = WriteOptions::new();
        let ack = self.db.write(write_opts, batch);
        match ack {
            Ok(_) => Ok(()),
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn delete(&self, key: i32) -> Result<(), Error> {
        let batch = &mut Writebatch::new();
        batch.delete(key);
        let write_opts = WriteOptions::new();
        let ack = self.db.write(write_opts, batch);
        match ack {
            Ok(_) => Ok(()),
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn get(&self, key: i32) -> Vec<u8> {
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
}




