#![allow(unused)]
use super::keystore::{KeyFile, KeyStore};
use crate::swiss_knife::helper::{is_string_valid_ecdsa, read_file_by_lines};
use std::convert::TryFrom;
use themis::keys::EcdsaPublicKey;

pub struct BootStrap {
    init: bool,
    peers: Vec<EcdsaPublicKey>,
    local_dat: KeyStore,
}
impl BootStrap {
    pub fn new() -> Self {
        Self {
            init: false,
            peers: Vec::new(),
            local_dat: KeyStore::new(),
        }
    }

    pub fn setup(&mut self, vals: Option<Vec<String>>) {
        self.load_validators(vals);
        self.load_keypair();
        self.init = true;
    }

    pub fn setup_done(&self) -> bool {
        self.init
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
            let keys = read_file_by_lines(&path);
            if keys.is_err() {
                panic!("{}", keys.err().unwrap());
            }
            self.peers = keys.unwrap();
        }
    }

    fn load_keypair(&mut self) {
        if self.local_dat.key_pair.is_filled() {
            log::info!("key pair already exists");
            return;
        }

        let path: String = std::env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        let key_path = "/keyfile.dat";
        let mut path = path.clone();
        path.push_str(key_path);
        let data = match std::fs::read_to_string(&path) {
            Ok(dat) => dat,
            Err(e) => {
                panic!("could not read key file");
            }
        };

        let parsed_json = serde_json::from_str(&data);
        if parsed_json.is_err() {
            panic!("could not parse data as json");
        }
        let key_pair: KeyFile = parsed_json.unwrap();
        self.local_dat.key_pair = key_pair;
    }

    pub fn get_peers(&self) -> Vec<EcdsaPublicKey> {
        self.peers.clone()
    }

    pub fn amount_peers(&self) -> usize {
        self.peers.len() - 1 // we do not count ourself
    }

    pub fn get_public(&self) -> String {
        self.local_dat.get_public()
    }

    pub fn get_secret(&self) -> String {
        self.local_dat.get_secret()
    }
}
