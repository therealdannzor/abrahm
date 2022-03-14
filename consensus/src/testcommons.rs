#![allow(unused)]
use themis::keygen;
use themis::keys::EcdsaPublicKey;

pub fn generate_keys_as_str_and_type(amount: u8) -> (Vec<String>, Vec<EcdsaPublicKey>) {
    let mut string_result = Vec::new();
    let mut type_result = Vec::new();
    for _ in 0..amount {
        let (_, pk) = keygen::gen_ec_key_pair().split();
        type_result.push(pk.clone());
        let pk: String = hex::encode(pk);
        string_result.push(pk);
    }
    (string_result, type_result)
}
