use crate::swiss_knife::helper::hash_from_vec_u8_input;
use themis::keys::EcdsaPublicKey;
use themis::secure_message::SecureVerify;

pub enum Messages {
    Request,
    Preprepare,
    Prepare,
    Commit,
    Viewchange,
    NewView,
    Invalid,
}

pub fn parse_u8_to_enum(flag: u8) -> Messages {
    match flag {
        0 => Messages::Request,
        1 => Messages::Preprepare,
        2 => Messages::Prepare,
        3 => Messages::Commit,
        4 => Messages::Viewchange,
        5 => Messages::NewView,
        _ => Messages::Invalid,
    }
}

// Compares the hash of the plain text message with the decryption of the
// signed message received from the external connection. It uses the (known)
// public key of the foreign connection to decrypt its message.
pub fn cmp_message_with_signed_digest(
    public_key: EcdsaPublicKey,
    plain_message: Vec<u8>,
    signed_message: Vec<u8>,
) -> bool {
    let sv = SecureVerify::new(public_key);
    let decrypted = match sv.verify(signed_message) {
        Ok(m) => m,
        Err(e) => {
            log::error!("secure crypto verification failed: {:?}", e);
            return false;
        }
    };
    let plain_hashed = hash_from_vec_u8_input(plain_message).as_bytes().to_vec();
    decrypted == plain_hashed
}

pub fn u8_to_ascii_decimal(input: u8) -> Vec<u8> {
    let num: Vec<u8> = input
        .to_string()
        .chars()
        .map(|d| d.to_ascii_lowercase() as u8)
        .collect();
    num
}

#[allow(dead_code)]
pub fn usize_to_ascii_decimal(input: usize) -> Vec<u8> {
    let num: Vec<u8> = input
        .to_string()
        .chars()
        .map(|d| d.to_ascii_lowercase() as u8)
        .collect();
    num
}

pub fn vec_u8_ascii_decimal_to_u8(input: Vec<u8>) -> u8 {
    let input: &[u8] = &input;
    let mut acc = 0;
    for n in input {
        acc *= 10;
        acc += n;
    }
    acc
}

pub fn public_key_and_payload_to_vec(key: EcdsaPublicKey, msg: String) -> Vec<u8> {
    let mut enc_key = hex::encode(key).as_bytes().to_vec();
    let mut payload_as_bytes = msg.as_bytes().to_vec();
    enc_key.append(&mut payload_as_bytes);
    enc_key
}

const PUB_KEY_LEN: usize = 90;

// same length as both port and READY message
const MSG_LEN: usize = 10;
pub fn extract_signed_message(v: Vec<u8>) -> Vec<u8> {
    let size = v.len();
    // a hack to make sure that the signed message does not include
    // zeros that the peer never intended to be part of the message
    let last_three_elements = v[size - 3..].to_vec();
    let trailing_zeros = check_zeros(last_three_elements);
    v[PUB_KEY_LEN + MSG_LEN..size - trailing_zeros].to_vec()
}

fn check_zeros(v: Vec<u8>) -> usize {
    let mut result = 0;
    for num in v.iter() {
        if *num == 0 {
            result += 1;
        }
    }
    result
}
