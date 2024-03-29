use swiss_knife::helper::{hash_and_sign_message_digest, hash_from_vec_u8_input};
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

// Compares two public keys and returns the one which has the highest byte value (ascii code)
// starting from the leftmost bit. If they are equal, we move one step to the right.
// This is used to decide on message protocol priority when two peers have both sent a ping message
// to one another and need to decide on which of the two will respond with pong.
// This function returns the peer with the obligation to respond with pong.
pub fn cmp_two_keys(k1: EcdsaPublicKey, k2: EcdsaPublicKey) -> EcdsaPublicKey {
    let s1: Vec<u8> = hex::encode(k1.clone()).as_bytes().to_vec();
    let s2: Vec<u8> = hex::encode(k2.clone()).as_bytes().to_vec();
    let len = s1.len();

    for i in 0..len {
        if s1[i] > s2[i] {
            return k1;
        } else if s2[i] > s1[i] {
            return k2;
        } else {
            continue;
        }
    }
    log::error!("cmp_two_keys received the same key twice, return the first");
    // the (erroneous) edge case where the two keys are identical
    k1
}
pub fn cmp_two_keys_string(s1: String, s2: String) -> String {
    let b1 = s1.as_bytes();
    let b2 = s2.as_bytes();
    let len = b1.len();

    for i in 0..len {
        if b1[i] > b2[i] {
            return s1;
        } else if b2[i] > b1[i] {
            return s2;
        } else {
            continue;
        }
    }
    log::error!("cmp_two_keys_string received the same key twice, return the first");
    s1
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

pub fn create_short_message(id: u32, secret: EcdsaPrivateKey, msg: &str) -> Vec<u8> {
    let mut first_half = token_and_payload_to_vec(id, msg);
    let second_half = hash_and_sign_message_digest(secret, first_half.clone());
    first_half.extend(second_half);
    first_half
}

pub fn verify_p2p_message(message: Vec<u8>) -> (bool, EcdsaPublicKey) {
    let (_, dummy_pk) = themis::keygen::gen_ec_key_pair().split();
    let default_err_resp = (false, dummy_pk);
    let full_length = message.len();
    if full_length > 249 || full_length < 247 {
        log::error!("message length not between 247 and 249");
        return default_err_resp;
    }
    let public_key = match extract_pub_key_field(message.clone()) {
        Ok(k) => k,
        Err(e) => {
            log::error!("key extraction failed: {}", e);
            return default_err_resp;
        }
    };

    let public_key = match EcdsaPublicKey::try_from_slice(public_key) {
        Ok(k) => k,
        Err(e) => {
            log::error!("could not restore public key from slice: {}", e);
            return default_err_resp;
        }
    };

    let disc = extract_discv_port_field(message.clone());
    let disc_str = match std::str::from_utf8(&disc.clone()) {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("failure to convert discv port from utf-8 to string: {}", e);
            return default_err_resp;
        }
    };

    let srv_port = extract_server_port_field(message.clone());
    let srv_port = match std::str::from_utf8(&srv_port.clone()) {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("failure to convert server port from utf-8 to string: {}", e);
            return default_err_resp;
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

pub fn verify_root_hash_sync_message(
    message: Vec<u8>,
    local_root_hash: String,
    verif_key: EcdsaPublicKey,
) -> (bool, u8) {
    let default_err_resp = (false, 0);
    let short_id = message.to_vec()[0];
    if short_id < 48 || short_id > 57 {
        log::error!("incorrect id, must be between 0 and 9");
        return default_err_resp;
    }
    let root_hash_tag_len = 6;
    let expected_tag = "RTHASH".to_string().as_bytes().to_vec();
    if message[1..1 + root_hash_tag_len] != expected_tag {
        log::error!("incorrect message format, missing root hash tag");
        return default_err_resp;
    }
    let full_plaintext = extract_plain_root_field(message.clone());
    // id is 1 field, expected tag is 6 fields
    let just_root = full_plaintext[1 + expected_tag.len()..].to_vec();
    if just_root != local_root_hash.as_bytes().to_vec() {
        log::error!("local root hash different as to one local");
        return default_err_resp;
    }
    let plain_message = extract_plain_root_field(message.clone());
    let signed_message = extract_signed_root_hash(message);
    if !cmp_message_with_signed_digest(verif_key, plain_message, signed_message) {
        log::error!("could not verify root sync message");
        return default_err_resp;
    }

    (true, short_id)
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

pub fn extract_plain_root_field(v: Vec<u8>) -> Vec<u8> {
    let id_len = 1;
    let rh_tag = 6;
    let rh_len = 64;
    v[..id_len + rh_tag + rh_len].to_vec()
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

pub fn token_and_payload_to_vec(token: u32, msg: &str) -> Vec<u8> {
    let mut tok = token.to_string().as_bytes().to_vec();
    let msg = msg.to_string().as_bytes().to_vec();
    tok.extend(msg);
    tok
}

pub fn extract_signed_message(v: Vec<u8>) -> Vec<u8> {
    // same length as both port and READY message
    let msg_len: usize = 10;

    let size = v.len();
    // a hack to make sure that the signed message does not include
    // zeros that the peer never intended to be part of the message
    let last_three_elements = v[size - 3..].to_vec();
    let trailing_zeros = check_zeros(last_three_elements);
    v[PUB_KEY_LEN + msg_len..size - trailing_zeros].to_vec()
}

pub fn extract_signed_root_hash(v: Vec<u8>) -> Vec<u8> {
    let plain_index_up_to = 1 + 6 + 64;
    let signed_and_hash_len_max = 148;
    let slice = v[plain_index_up_to..plain_index_up_to + signed_and_hash_len_max].to_vec();
    let size = slice.len();
    let last_three_elements = slice[size - 3..].to_vec();
    let trailing_zeros = check_zeros(last_three_elements);
    v[plain_index_up_to..plain_index_up_to + signed_and_hash_len_max - trailing_zeros].to_vec()
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
