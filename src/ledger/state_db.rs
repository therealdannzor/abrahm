extern crate rocksdb;
use rocksdb::{Options, DB};
use themis::keys::EcdsaPublicKey;

extern crate crypto;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

pub trait KeyValueIO {
    // new creates a new key-value reader-writer
    fn new(path: &str) -> StateDB;

    // put inserts the key-value pair in the data storage
    fn put(&mut self, key: EcdsaPublicKey, value: &str);

    // delete removes the key from the data storage
    fn delete(&mut self, key: EcdsaPublicKey);

    // get_value retrieves the value of the key if it exists. If it is does not
    // it returns a dummy ouput of 0.
    fn get_value(&self, key: EcdsaPublicKey) -> String;

    // update_root_hash receives a key-value pair and creates a hash
    // based on the existing root hash and this pair to represent a
    // simple and traceable transition of state change
    fn update_root_hash(&mut self, key: EcdsaPublicKey, val: &str);

    // get_root_hash retrieves the root hash of the state db which represents
    // the freshest and latest change to the db
    fn get_root_hash(&self) -> String;
}

pub struct StateDB {
    // The leveldb database
    db: DB,

    // The hash of all the states. Each state consists of a key-value pair
    // which represents the account and its balance.
    root_hash: String,
}

impl KeyValueIO for StateDB {
    fn new(path: &str) -> StateDB {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let database = DB::open_default(path).unwrap();

        let mut hasher = Sha256::new();
        hasher.input(b"AbrahmChain");
        let hash_out = hasher.result_str();

        StateDB {
            db: database,
            root_hash: hash_out,
        }
    }

    fn put(&mut self, key: EcdsaPublicKey, val: &str) {
        if val == "" {
            return;
        }

        let res = &self.db.put(key.clone(), val);
        match res {
            Ok(_) => self.update_root_hash(key.clone(), val),
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn delete(&mut self, key: EcdsaPublicKey) {
        let bal = self.get_value(key.clone());
        if bal == "0" {
            return;
        }

        let ack = &self.db.delete(key.clone());
        match ack {
            Ok(_) => {
                self.update_root_hash(key, &"0".to_string());
            }
            Err(e) => panic!("write db error: {:?}", e),
        }
    }

    fn get_value(&self, key: EcdsaPublicKey) -> String {
        let res = &self.db.get(key);
        match res {
            Ok(Some(value)) => std::str::from_utf8(&value).unwrap().to_string(),
            Ok(None) => "0".to_string(), // dummy output (missing value)
            Err(e) => panic!("read db error: {:?}", e),
        }
    }

    fn update_root_hash(&mut self, key: EcdsaPublicKey, val: &str) {
        let mut input = self.root_hash.clone();
        input.push_str(&val);
        let mut new_hash = Sha256::new();
        new_hash.input(key.as_ref());
        new_hash.input_str(&input);

        self.root_hash = new_hash.result_str()
    }

    fn get_root_hash(&self) -> String {
        self.root_hash.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use themis::keygen::gen_ec_key_pair;
    use themis::keys::EcdsaPublicKey;

    fn new_pub_key() -> EcdsaPublicKey {
        let (_, pk) = gen_ec_key_pair().split();
        pk
    }

    #[test]
    #[serial]
    fn new_insert_expect_new_state_change() {
        let mut db = setup();
        let root = db.get_root_hash();

        // fund account 1 with a balance
        let pk1 = new_pub_key();
        db.put(pk1.clone(), "2");
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(pk1.clone()), "2");
        let root = new_root;

        // fund account 2 with a balance
        let pk2 = new_pub_key();
        db.put(pk2.clone(), "3");
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(pk2), "3");

        db.delete(pk1.clone());
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(pk1.clone()), "0");
        let root = new_root;

        let pk_uknown = new_pub_key();
        db.delete(pk_uknown); // does not exist
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);
    }

    #[test]
    #[serial]
    fn new_insert_and_delete_expect_new_state() {
        let mut db = setup();
        let root = db.get_root_hash();

        let pk1 = new_pub_key();
        db.put(pk1.clone(), "2");
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(pk1.clone()), "2");
        let root = new_root;

        // remove all non-nil balance from account 1
        db.delete(pk1.clone());
        let new_root = db.get_root_hash();
        assert_ne!(root, new_root);
        assert_eq!(db.get_value(pk1.clone()), "0");
    }

    #[test]
    #[serial]
    fn delete_missing_key_expect_no_state_change() {
        let mut db = setup();

        let pk1 = new_pub_key();
        db.put(pk1, "2");
        let root = db.get_root_hash();
        // send a delete cmd to a key which is missing
        let pk5 = new_pub_key();
        db.delete(pk5);
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);
    }

    #[test]
    #[serial]
    fn delete_key_with_no_balance_expect_no_state_change() {
        let mut db = setup();

        let pk = new_pub_key();
        db.put(pk.clone(), "0");
        let root = db.get_root_hash();
        // send delete cmd to a key which has no balance
        db.delete(pk.clone());
        let new_root = db.get_root_hash();
        assert_eq!(root, new_root);
    }

    #[test]
    #[serial]
    fn add_large_value_expect_state_change() {
        let mut db = setup();

        let genesis_root = db.get_root_hash();
        let pk = new_pub_key();
        db.put(pk, "10000000000000000000");
        let root = db.get_root_hash();
        assert_ne!(genesis_root, root);
    }

    #[test]
    #[serial]
    fn empty_value_expect_no_state_change() {
        let mut db = setup();
        let genesis_root = db.get_root_hash();

        let pk = new_pub_key();
        db.put(pk, "");
        let root = db.get_root_hash();
        assert_eq!(genesis_root, root);
    }

    fn setup() -> StateDB {
        let mut tmp_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        tmp_path.push_str("/test");

        let _rmd = std::fs::remove_dir_all(&tmp_path);
        let _crd = std::fs::create_dir(&tmp_path);

        StateDB::new(&tmp_path)
    }
}
