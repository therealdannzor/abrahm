#[path = "./helper.rs"]
mod helper;

use themis::keygen::gen_ec_key_pair;
use std::env;

extern crate hex;

pub struct AccountID {
    // The account identifier (in hexadecimal)
    pub address: String,
    // The file path to the secret key
    pub key_path: String,
    // The monotonic increasing count of transactions 
    pub tx_count: u16,
}

impl AccountID {
    pub fn new() -> Self {
        // get path to the root of the project (location of cargo manifest)
        let cargo_path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        // decide relative path of keys
        let private_key = "/private.key";
        let public_key = "/public.key";
        // apppend key paths to cargo path
        let mut secret_path = cargo_path.clone();
        secret_path.push_str(private_key);
        let mut public_path = cargo_path.clone();
        public_path.push_str(public_key);

        // generate public-private keypair
        let (secret_key, public_key) = gen_ec_key_pair().split();
        // convert public key to hexadecimal string as a more readable ID
        let public_hex: String = hex::encode(public_key);
        match helper::write_file(&secret_key, &secret_path) {
            Ok(_) => (),
            Err(e) => eprintln!{"failed to create secret key at: {}, error: {}", secret_path, e},
        }
        match helper::write_file(&public_hex, &public_path) {
            Ok(_) => (),
            Err(e) => eprintln!{"failed to save public key at: {}, error: {}", public_path, e},
        }

        let account_address = helper::remove_trail_chars(public_hex);
        match account_address {
            Some(_) => (),
            None => {
                panic!("failed to parse public key string");
            }
        }

        Self {
            address: account_address.unwrap(),
            key_path: secret_path,
            tx_count: 0,
        }

    }
}

