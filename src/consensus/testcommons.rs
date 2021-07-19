use themis::keygen;
use themis::keys::EcdsaPublicKey;

pub fn generate_keys(amount: u8) -> Vec<EcdsaPublicKey> {
    let mut result = Vec::new();
    for _ in 0..amount {
        let (_, pk) = keygen::gen_ec_key_pair().split();
        result.push(pk);
    }
    result
}
