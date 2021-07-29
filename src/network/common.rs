use crate::hashed;
use crate::swiss_knife::helper::generate_hash_from_input;
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
    let secure_b = SecureVerify::new(public_key);
    let recv = secure_b.verify(signed_message);
    if recv.is_err() {
        return false;
    }
    let recv = recv.unwrap();

    let plain_message = std::str::from_utf8(&plain_message);
    if plain_message.is_err() {
        log::debug!("cmp message: could not parse plain message to utf-8");
        return false;
    }

    let m_hashed = hashed!(plain_message.unwrap());
    let recv = std::str::from_utf8(&recv);
    if recv.is_err() {
        log::debug!("cmp message: received message is not utf-8");
        return false;
    }
    m_hashed == recv.unwrap()
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
