use crate::swiss_knife::helper::{hash_and_sign_message_digest, hash_from_vec_u8_input};
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
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

// Creates a p2p message with the public key (in hex) as ID and the payload in both plain text and
// as a signed digest
pub fn create_p2p_message(
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    msg: &str,
) -> Vec<u8> {
    let mut result = Vec::new();
    // First half is PUBLIC_KEY | MSG (in bytes)
    let first_half = public_key_and_payload_to_vec(public_key, msg.to_string());
    // Second half is H(PUBLIC_KEY | MSG)_C (in bytes)
    let second_half = hash_and_sign_message_digest(secret_key, first_half.clone());

    result.extend(first_half);
    result.extend(second_half);

    result
}

pub fn verify_p2p_message(message: Vec<u8>) -> (bool, EcdsaPublicKey) {
    let (_, dummy_pk) = themis::keygen::gen_ec_key_pair().split();
    let full_length = message.len();
    if full_length > 248 || full_length < 246 {
        log::error!("message length not between 246 and 248");
        return (false, dummy_pk);
    }
    let public_key = match extract_pub_key_field(message.clone()) {
        Ok(k) => k,
        Err(e) => {
            log::error!("key extraction failed: {}", e);
            return (false, dummy_pk);
        }
    };

    let public_key = match EcdsaPublicKey::try_from_slice(public_key) {
        Ok(k) => k,
        Err(e) => {
            log::error!("could not restore public key from slice: {}", e);
            return (false, dummy_pk);
        }
    };

    let disc = extract_discv_port_field(message.clone());
    let disc_str = match std::str::from_utf8(&disc.clone()) {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("failure to convert discv port from utf-8 to string: {}", e);
            return (false, dummy_pk);
        }
    };

    let srv_port = extract_server_port_field(message.clone());
    let srv_port = match std::str::from_utf8(&srv_port.clone()) {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("failure to convert server port from utf-8 to string: {}", e);
            return (false, dummy_pk);
        }
    };

    let mut payload = "".to_string();
    payload.push_str(&disc_str);
    payload.push_str(&srv_port);

    //  Important to encode to hex again to mimic the process of how the sender
    //  created this message. If not, the public key will only be 45 character as
    //  opposed to the 90 characters it is in hex form.
    let plain_message = public_key_and_payload_to_vec(public_key.clone(), payload);

    let signed_message = extract_signed_message(message);

    let auth_ok = cmp_message_with_signed_digest(public_key.clone(), plain_message, signed_message);
    (auth_ok, public_key)
}

const PUB_KEY_LEN: usize = 90;
const SRV_PORT_LEN: usize = 5;

pub fn extract_pub_key_field(v: Vec<u8>) -> Result<Vec<u8>, hex::FromHexError> {
    let v = v[..PUB_KEY_LEN].to_vec();
    Ok(hex::decode(v)?)
}

pub fn extract_discv_port_field(v: Vec<u8>) -> Vec<u8> {
    v[PUB_KEY_LEN..PUB_KEY_LEN + SRV_PORT_LEN].to_vec()
}

pub fn extract_server_port_field(v: Vec<u8>) -> Vec<u8> {
    v[PUB_KEY_LEN + SRV_PORT_LEN..PUB_KEY_LEN + 2 * SRV_PORT_LEN].to_vec()
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
