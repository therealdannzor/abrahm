use chrono::prelude::Utc;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fs::File;
use std::io::{BufRead, BufReader, Lines, Write};
use themis::keys::EcdsaPublicKey;

pub fn write_file<K: AsRef<[u8]>>(key: K, path: &str) -> std::io::Result<()> {
    // no matter where we are in the project folder, always save the keys in the same
    // directory as the cargo manifest
    let new_path = remove_suffix(&path, "/src");
    let mut file = std::fs::File::create(new_path)?;
    file.write_all(key.as_ref())?;
    Ok(())
}

pub fn read_file_by_lines(path: &str) -> Result<Vec<EcdsaPublicKey>, std::io::Error> {
    let mut keys = Vec::new();
    if let Ok(lines) = read_lines(path) {
        for line in lines {
            if line.is_err() {
                return Err(line.err().unwrap());
            }
            let line = line.unwrap();
            let key = is_string_valid_ecdsa(line);
            if key.is_err() {
                return Err(key.err().unwrap());
            }
            let key = key.unwrap();
            keys.push(key);
        }
        if keys.len() < 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "found less than four validators",
            ));
        }
        return Ok(keys);
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "couldn not read lines",
        ));
    }
}

fn read_lines<P>(filename: P) -> std::io::Result<Lines<BufReader<File>>>
where
    P: AsRef<std::path::Path>,
{
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

pub fn is_string_valid_ecdsa(key: String) -> Result<EcdsaPublicKey, std::io::Error> {
    let key = match hex::decode(key) {
        Ok(k) => k,
        Err(e) => {
            panic!("could not decode key: {:?}", e);
        }
    };

    match themis::keys::EcdsaPublicKey::try_from_slice(key) {
        Ok(k) => Ok(k),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "string is not a valid EcdsaPublicKey: {:?}",
            ));
        }
    }
}

pub fn remove_suffix<'a>(s: &'a &str, p: &str) -> &'a str {
    if s.ends_with(p) {
        &s[..s.len() - p.len()]
    } else {
        s
    }
}

#[allow(unused)]
pub fn remove_trail_chars(s: String) -> Option<String> {
    // check we have a full public key string
    if s.len() == 90 {
        // let the last 40 characters be the account address
        Some(s[50..].to_string())
    } else {
        None
    }
}
pub fn generate_hash_from_input(inp: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input(inp.as_bytes());
    let hash_out = hasher.result_str();
    hash_out
}

pub fn hash_from_vec_u8_input(inp: Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.input(&inp);
    hasher.result_str()
}

pub fn new_timestamp() -> i64 {
    Utc::now().timestamp_millis()
}

pub fn hash_and_sign_message_digest(
    secret_key: themis::keys::EcdsaPrivateKey,
    message: Vec<u8>,
) -> Vec<u8> {
    let m_d = hash_from_vec_u8_input(message);
    let sec_message = themis::secure_message::SecureSign::new(secret_key.clone());
    let sign_m_d = match sec_message.sign(&m_d) {
        Ok(m) => m,
        Err(e) => panic!("failed to sign message: {:?}", e),
    };
    sign_m_d
}

#[macro_export]
macro_rules! hashed {
    ($x:expr) => {
        generate_hash_from_input($x)
    };
}
