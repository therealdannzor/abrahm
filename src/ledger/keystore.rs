use crate::swiss_knife::helper;
use serde::{Deserialize, Serialize};
use std::env;
use themis::keygen::gen_ec_key_pair;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};

pub struct KeyStore {
    // The account identifier (in hexadecimal)
    pub key_pair_hex: KeyFile,
    // The account indentifier (in native type)
    pub key_pair_as_type: KeyPairAsType,
    // The file path to the secret key
    pub key_path: String,
    // The monotonic increasing count of transactions
    pub tx_count: u16,
}

#[derive(Deserialize, Serialize)]
pub struct KeyFile {
    public_hex: String,
    secret_hex: String,
}
impl KeyFile {
    pub fn new(public_hex: String, secret_hex: String) -> Self {
        Self {
            public_hex,
            secret_hex,
        }
    }

    pub fn is_filled(&self) -> bool {
        self.public_hex != "" && self.secret_hex != ""
    }
}

pub struct KeyPairAsType {
    public: EcdsaPublicKey,
    secret: EcdsaPrivateKey,
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
        let key_native_type = KeyPairAsType {
            public: public_key.clone(),
            secret: secret_key.clone(),
        };

        // convert public key to hexadecimal string as a more readable ID
        let public_hex: String = hex::encode(public_key);
        let secret_hex: String = hex::encode(secret_key);
        let key_pair_hex = KeyFile::new(public_hex, secret_hex);
        let key_json = match serde_json::to_string(&key_pair_hex) {
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
            key_pair_hex,
            key_pair_as_type: key_native_type,
            key_path: secret_path,
            tx_count: 0,
        }
    }

    pub fn get_public_hex(&self) -> String {
        self.key_pair_hex.public_hex.clone()
    }

    pub fn get_public_as_type(&self) -> EcdsaPublicKey {
        self.key_pair_as_type.public.clone()
    }

    pub fn get_secret_as_type(&self) -> EcdsaPrivateKey {
        self.key_pair_as_type.secret.clone()
    }
}
