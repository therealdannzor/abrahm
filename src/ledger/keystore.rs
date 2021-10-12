use crate::swiss_knife::helper;
use serde::{Deserialize, Serialize};
use std::env;
use themis::keygen::gen_ec_key_pair;

pub struct KeyStore {
    // The account identifier (in hexadecimal)
    pub key_pair: KeyFile,
    // The file path to the secret key
    pub key_path: String,
    // The monotonic increasing count of transactions
    pub tx_count: u16,
}

#[derive(Deserialize, Serialize)]
pub struct KeyFile {
    public: String,
    secret: String,
}
impl KeyFile {
    pub fn new(public: String, secret: String) -> Self {
        Self { public, secret }
    }

    pub fn is_filled(&self) -> bool {
        self.public != "" && self.secret != ""
    }
}

impl KeyStore {
    pub fn new() -> Self {
        // get path to the root of the project (location of cargo manifest)
        let cargo_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();

        // decide relative path of key pair
        let key_path = "/keyfile.dat";

        // apppend key path to cargo path
        let mut secret_path = cargo_path.clone();
        secret_path.push_str(key_path);

        // generate public-private key pair
        let (secret_key, public_key) = gen_ec_key_pair().split();

        // convert public key to hexadecimal string as a more readable ID
        let public_hex: String = hex::encode(public_key.clone());
        let secret_hex: String = hex::encode(secret_key);
        let key_pair = KeyFile::new(public_hex, secret_hex);
        let key_json = match serde_json::to_string(&key_pair) {
            Ok(json) => json,
            Err(e) => {
                panic!("failed to parse fmt key pair: {:?}", e)
            }
        };

        match helper::write_file(&key_json, &secret_path) {
            Ok(_) => (),
            Err(e) => eprintln! {"failed to create secret key at: {}, error: {}", secret_path, e},
        }

        Self {
            key_pair,
            key_path: secret_path,
            tx_count: 0,
        }
    }
}
