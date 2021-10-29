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
        for i in 0..4 {
            let mut path = create_node_key_path(i);
            let _ = match std::fs::metadata(path.clone()) {
                Ok(_) => continue,
                Err(_) => {
                    let _ = std::fs::create_dir_all(&path);
                    // generate public-private key pair
                    let (secret_key, public_key) = gen_ec_key_pair().split();

                    // convert public key to hexadecimal string to be more readable
                    let public_hex: String = hex::encode(public_key.clone());
                    let secret_hex: String = hex::encode(secret_key.clone());

                    let key_pair_hex = KeyFile::new(public_hex, secret_hex);
                    let key_json = match serde_json::to_string(&key_pair_hex) {
                        Ok(json) => json,
                        Err(e) => {
                            panic!("failed to parse fmt key pair: {:?}", e)
                        }
                    };

                    path.push_str("/keyfile.dat");
                    match helper::write_file(&key_json, &path) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln! {"failed to create secret key at: {}, error: {}", path, e}
                        }
                    }
                }
            };
        }

        // based on cli arg, we set one of the keypairs as the local node / peer ID
        let local_node_dir = create_node_key_path(index);
        let (sk_hex, pk_hex) = read_keyfile_json(local_node_dir.clone());
        let mut sk_bytes = sk_hex.clone().into_bytes();
        // remove quotation marks in the beginning and the end of the byte vector
        sk_bytes.remove(0);
        sk_bytes.remove(sk_bytes.len() - 1);
        let sk_vec = match hex::decode(sk_bytes) {
            Ok(s) => s,
            Err(e) => {
                panic!("failed to decode secret key hex string: {}", e);
            }
        };
        let local_sec_type = match EcdsaPrivateKey::try_from_slice(sk_vec) {
            Ok(s) => s,
            Err(e) => {
                panic!("failed to re-create secret key from string: {}", e);
            }
        };

        let mut pk_bytes = pk_hex.clone().into_bytes();
        // remove quotation marks in the beginning and the end of the byte vector
        pk_bytes.remove(0);
        pk_bytes.remove(pk_bytes.len() - 1);
        let pk_vec = match hex::decode(pk_bytes) {
            Ok(s) => s,
            Err(e) => {
                panic!("failed to decode public key hex string: {}", e);
            }
        };
        let local_pub_type = match EcdsaPublicKey::try_from_slice(pk_vec) {
            Ok(s) => s,
            Err(e) => {
                panic!("failed to re-create public key from string: {}", e);
            }
        };

        let key_pair_hex = KeyFile {
            public_hex: pk_hex.clone(),
            secret_hex: sk_hex.clone(),
        };
        let key_pair_as_type = KeyPairAsType {
            public: local_pub_type,
            secret: local_sec_type,
        };

        Self {
            key_pair_hex,
            key_pair_as_type,
            key_path: local_node_dir,
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

fn read_keyfile_json(mut path: String) -> (String, String) {
    path.push_str("/keyfile.dat");
    let json_fp = std::path::Path::new(&path);
    let file = std::fs::File::open(json_fp).expect("file not found");
    let keypair: serde_json::Value = serde_json::from_reader(file).expect("could not read file");

    let sk = keypair["secret_hex"].to_string();
    let pk = keypair["public_hex"].to_string();

    (sk, pk)
}

fn create_node_key_path(id: u32) -> String {
    let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
    path.push_str("/keys/node");
    let digit = std::char::from_digit(id, 10).unwrap();
    path.push(digit);
    path
}
