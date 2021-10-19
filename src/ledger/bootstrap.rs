use super::keystore::{KeyFile, KeyStore};
use crate::swiss_knife::helper::{is_string_valid_ecdsa, read_file_by_lines};
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};

pub struct BootStrap {
    peers: Vec<EcdsaPublicKey>,
    local_dat: KeyStore,
    node_index: u32,
}
impl BootStrap {
    pub fn new(node_index: u32) -> Self {
        Self {
            peers: Vec::new(),
            local_dat: KeyStore::new(node_index),
            node_index,
        }
    }

    pub fn setup(&mut self, vals: Option<Vec<String>>) {
        self.load_validators(vals);
        self.load_keypair();
    }

    fn load_validators(&mut self, vals: Option<Vec<String>>) {
        if self.peers.len() > 0 {
            panic!("validators already exists");
        }
        // either pass the validators as a vector of strings directly
        if vals.is_some() {
            let vals = vals.unwrap();
            if vals.len() < 3 {
                panic!("provided less than three other validators");
            }
            for v in vals.iter() {
                let key = is_string_valid_ecdsa(v.to_string());
                if key.is_err() {
                    panic!("{}", key.err().unwrap());
                }
                self.peers.push(key.unwrap());
            }
            // or read a file with the validators line separated
        } else {
            let path: String =
                std::env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
            let validator_path = "/validators.txt";
            let mut path = path.clone();
            path.push_str(validator_path);
            let keys = match read_file_by_lines(&path) {
                Ok(k) => k,
                Err(e) => {
                    panic!("validator public key not valid: {:?}", e);
                }
            };
            self.peers = keys;
        }
    }

    fn load_keypair(&mut self) {
        let node_id = self.node_index.clone();
        if self.local_dat.key_pair_hex.is_filled() {
            log::info!("key pair already exists");
            return;
        }

        let path: String = std::env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        let key_path = format!(
            "/keys/node{}/keyfile.dat",
            std::char::from_digit(node_id, 10).unwrap()
        );
        let mut path = path.clone();
        path.push_str(&key_path);
        let data = match std::fs::read_to_string(&path) {
            Ok(dat) => dat,
            Err(e) => {
                panic!("could not read key file: {:?}", e);
            }
        };

        let parsed_json = serde_json::from_str(&data);
        if parsed_json.is_err() {
            panic!("could not parse data as json");
        }
        let key_pair: KeyFile = parsed_json.unwrap();
        self.local_dat.key_pair_hex = key_pair;

        let pub_key = self.get_public_hex();
        match hex::decode(pub_key) {
            Ok(_) => {}
            Err(e) => {
                panic!(
                    "public key provided through key file is not a hex string: {:?}",
                    e
                );
            }
        }
    }

    pub fn get_peers(&self) -> Vec<EcdsaPublicKey> {
        self.peers.clone()
    }

    pub fn get_peers_str(&self) -> Vec<String> {
        let peers = self.get_peers();
        let mut result: Vec<String> = Vec::new();
        for i in 0..peers.len() {
            let public_hex: String = hex::encode(peers[i].clone());
            result.push(public_hex);
        }
        result
    }

    pub fn get_public_hex(&self) -> String {
        self.local_dat.get_public_hex()
    }

    pub fn get_public_as_type(&self) -> EcdsaPublicKey {
        self.local_dat.get_public_as_type()
    }

    pub fn get_secret_as_type(&self) -> EcdsaPrivateKey {
        self.local_dat.get_secret_as_type()
    }
}
