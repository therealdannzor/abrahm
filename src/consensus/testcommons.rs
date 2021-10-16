#![allow(unused)]
use themis::keygen;

pub fn generate_keys_as_str(amount: u8) -> Vec<String> {
    let mut result = Vec::new();
    for _ in 0..amount {
        let (_, pk) = keygen::gen_ec_key_pair().split();
        let pk: String = hex::encode(pk);
        result.push(pk);
    }
    result
}
