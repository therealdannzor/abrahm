use crate::swiss_knife::helper;
use serde::{Deserialize, Serialize};
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
    pub fn new(index: u32) -> Self {
        // dummy initializes
        let mut local_pub_key = "".to_string();
        let mut local_sec_key = "".to_string();
        let (mut local_sec_type, mut local_pub_type) = gen_ec_key_pair().split();
        let mut local_key_path = "".to_string();

        let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        path.push_str("/keys/node");

        for i in 0..4 {
            let mut copy_path = path.clone();
            let digit = std::char::from_digit(i, 10).unwrap();
            copy_path.push(digit);
            let _ = match std::fs::metadata(copy_path.clone()) {
                Ok(_) => continue,
                Err(_) => {
                    let _ = std::fs::create_dir_all(&copy_path);
                    // generate public-private key pair
                    let (secret_key, public_key) = gen_ec_key_pair().split();

                    // convert public key to hexadecimal string as a more readable ID
                    let public_hex: String = hex::encode(public_key.clone());
                    let secret_hex: String = hex::encode(secret_key.clone());
                    // based on cli arg, we set one of the keypairs as the local node/peers ID
                    if i == index {
                        local_pub_key = public_hex.clone();
                        local_sec_key = secret_hex.clone();
                        local_pub_type = public_key.clone();
                        local_sec_type = secret_key.clone();
                        local_key_path = copy_path.clone();
                    }

                    let key_pair_hex = KeyFile::new(public_hex, secret_hex);
                    let key_json = match serde_json::to_string(&key_pair_hex) {
                        Ok(json) => json,
                        Err(e) => {
                            panic!("failed to parse fmt key pair: {:?}", e)
                        }
                    };

                    copy_path.push_str("/keyfile.dat");
                    match helper::write_file(&key_json, &copy_path) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln! {"failed to create secret key at: {}, error: {}", copy_path, e}
                        }
                    }
                }
            };
        }

        let key_pair_hex = KeyFile {
            public_hex: local_pub_key,
            secret_hex: local_sec_key,
        };
        let key_pair_as_type = KeyPairAsType {
            public: local_pub_type,
            secret: local_sec_type,
        };

        Self {
            key_pair_hex,
            key_pair_as_type,
            key_path: local_key_path,
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
