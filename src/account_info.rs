use themis::keygen::gen_ec_key_pair;
use std::io::Write;
use std::env;

extern crate hex;

pub struct AccountID {
    // The account identifier (in hexadecimal)
    address: String,
    // The file path to the secret key
    key_path: String,
    // The monotonic increasing count of transactions 
    tx_count: u16,
}

impl AccountID {
    pub fn new() -> AccountID {
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
        match write_file(&secret_key, &secret_path) {
            Ok(_) => (),
            Err(e) => eprintln!{"failed to create secret key at: {}, error: {}", secret_path, e},
        }
        match write_file(&public_hex, &public_path) {
            Ok(_) => (),
            Err(e) => eprintln!{"failed to save public key at: {}, error: {}", public_path, e},
        }
        
    
        let account_address = remove_trail_chars(public_hex);
        match account_address {
            Some(_) => (),
            None => {
                panic!("failed to parse public key string");
            }
        }

        let account_id = AccountID{
            address: account_address.unwrap(),
            key_path: secret_path,
            tx_count: 0,
        };

        println!{"Address: {}, path: {}, tx_count: {}",
        account_id.address, account_id.key_path, account_id.tx_count};

        return account_id
    }


}


fn write_file<K: AsRef<[u8]>>(key: K, path: &str) -> std::io::Result<()> {
    // no matter where we are in the project folder, always save the keys in the same
    // directory as the cargo manifest
    let new_path = remove_suffix(&path, "/src");
    let mut f = std::fs::File::create(new_path)?;
    f.write_all(key.as_ref())?;
    Ok(())
}

fn remove_suffix<'a>(s: &'a &str, p: &str) -> &'a str {
    if s.ends_with(p){
        &s[..s.len() - p.len()]
    } else {
        s
    }
}

fn remove_trail_chars(s: String) -> Option<String> {
    // check we have a full public key string
    if s.len() == 90 {
        // let the last 40 characters be the account address
        Some(s[50..].to_string())
    } else {
        None
    }
}
