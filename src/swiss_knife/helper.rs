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
        if keys.len() < 4 {
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
    let key: &[u8] = key.as_ref();
    let maybe_valid = themis::keys::EcdsaPublicKey::try_from_slice(key);
    if maybe_valid.is_err() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "string is not a valid EcdsaPublicKey",
        ));
    }
    Ok(maybe_valid.unwrap())
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

pub fn new_timestamp() -> i64 {
    Utc::now().timestamp_millis()
}

pub fn sign_message_digest(secret_key: themis::keys::EcdsaPrivateKey, message: &str) -> Vec<u8> {
    let m_d = generate_hash_from_input(message);
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
