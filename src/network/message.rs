#![allow(unused)]

use serde::ser::Error;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use themis::keygen;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey, PublicKey};
use themis::secure_message::{SecureSign, SecureVerify};

use crate::consensus::request::Request;
use crate::hashed;
use crate::swiss_knife::helper::generate_hash_from_input;

pub struct MessageWorker {
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    peer_shortnames: HashMap<u8, EcdsaPublicKey>,
}
impl MessageWorker {
    pub fn new(secret_key: EcdsaPrivateKey, public_key: EcdsaPublicKey) -> Self {
        Self {
            public_key,
            secret_key,
            peer_shortnames: HashMap::new(),
        }
    }

    pub fn sign_message_digest(&self, message: &str) -> Vec<u8> {
        let m_d = hashed!(message);
        let sec_message = SecureSign::new(self.secret_key.clone());
        let sign_m_d = match sec_message.sign(&m_d) {
            Ok(m) => m,
            Err(e) => panic!("failed to sign message: {:?}", e),
        };
        sign_m_d
    }

    pub fn insert_peer(&mut self, key: u8, value: EcdsaPublicKey) {
        self.peer_shortnames.insert(key, value);
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref().clone()
    }

    // The message structure is as follows:
    //
    // * identity (1 character, a single digit identifier mapped to a public key)
    // * message type flag (1 character, covers both transaction and consensus);
    // * message payload length flag (3 characters)
    // * serialized message (varying length, indicated by previous length flag)
    // * signed message digest (the rest of the message, does not matter that its length
    //   differs with ¬± 2 chars, althought it could be interesting to understand as an
    //   exercise TODO: investigate!)
    pub fn validate_received(&self, message: Vec<u8>) -> bool {
        // TODO: find the lowest bound of message length
        if message.len() < 10 {
            log::debug!("validate message: length less than expected");
            // guesstimation
            return false;
        }
        let targ_short_id = message[0];
        let targ_pub_key = self.peer_shortnames.get(&targ_short_id);
        if targ_pub_key.is_none() {
            log::debug!("validate message: missing public key from other peer");
            return false;
        }

        let targ_pub_key = targ_pub_key.unwrap();
        let consensus_round_type = message[1];
        if consensus_round_type > 5 {
            log::debug!("validate message: invalid consensus message flag");
            return false;
        }

        let consensus_round = parse_u8_to_enum(consensus_round_type);

        let mut payload_len: usize = 0;
        for i in 0..3 {
            let ch = message[2 + i] as char;
            let dig = ch.to_digit(10);
            if dig.is_some() {
                payload_len += dig.unwrap() as usize;
            }
        }

        if payload_len == 0 {
            log::debug!("validate message: undefined message payload");
            return false;
        }

        let payload = &message[5..payload_len + 5];
        let try_utf8 = std::str::from_utf8(payload);
        if try_utf8.is_err() {
            log::debug!("validate message: could not convert payload to utf8");
            return false;
        }
        let payload: Vec<u8> = payload.to_vec();

        let claimed_signed = message[payload_len + 5..].to_vec();
        if !cmp_message_with_signed_digest(targ_pub_key.clone(), payload, claimed_signed) {
            log::debug!("validate message: message authenticity mismatch");
            return false;
        }

        true
    }
}

pub fn validate_public_key(key: &[u8]) -> Option<PublicKey> {
    match PublicKey::try_from_slice(key) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

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
    m_hashed == recv.unwrap()
}

mod tests {

    use super::*;
    use crate::consensus::request::Request;
    use crate::consensus::transition::{Transact, Transition};
    use crate::hashed;
    use crate::swiss_knife::helper::generate_hash_from_input;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use themis::keys::PublicKey;
    use themis::secure_message::{SecureSign, SecureVerify};

    #[test]
    pub fn ijk() {
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk, pk.clone());
        mw.insert_peer(1, pk.clone());
        let signed = mw.sign_message_digest(&String::from("555555"));
        let mut msg = vec![1, 0, 0, 0, 54, 53, 53, 53, 53, 53, 53];
        msg.extend(signed);
        let res = mw.validate_received(msg);
        assert_eq!(res, true);
    }

    fn create_request_type(account: &str, from: &str, to: &str, amount: i32) -> Request {
        let next_transition = Transition::new("0x", vec![Transact::new(from, to, amount)]);
        Request::new(next_transition, "id")
    }

    #[test]
    fn abc() {
        let (other_peer_sk, other_peer_pk) = keygen::gen_ec_key_pair().split();

        let mw = MessageWorker::new(other_peer_sk, other_peer_pk.clone());

        // assumed to be stored by each client at initialization
        let mut mock_public_key_id_map = HashMap::<u8, EcdsaPublicKey>::new();
        mock_public_key_id_map.insert(1, other_peer_pk);

        let request = create_request_type("0x", "Alice", "Bob", 1);

        // first part of the message (public key)
        let target_id = u8::from(1);

        // second part of the message (single byte representing message type)
        let type_flag = u8::from(0);

        // third and fourth part of the message (request length )
        let serialized = serde_json::to_string(&request);
        if serialized.is_err() {
            panic!("error serializing: {:?}", serialized.unwrap());
        }
        let message_length = u8::try_from(serialized.as_ref().unwrap().len());
        if message_length.is_err() {
            panic!(
                "error message length overflow, maximum is 255, got: {}",
                message_length.unwrap()
            );
        }
        let message_length = message_length.unwrap();

        // prepare to sign the request
        let signed_request = mw.sign_message_digest(&hashed!(&serialized.as_ref().unwrap()));

        // add all components to a complete message
        let mut full_message = Vec::new();
        full_message.push(target_id);
        full_message.push(type_flag);
        full_message.push(message_length);
        full_message.extend(serialized.unwrap().as_bytes().to_vec());
        full_message.extend(signed_request);
    }

    #[test]
    fn xyz() {
        let (sk, mut pk) = keygen::gen_ec_key_pair().split();
        let mut ma = MessageWorker::new(sk, pk);

        // client creating a secret message and goes through the rituals
        let message = b"secretsecret";
        let secure_message = SecureSign::new(ma.secret_key.clone());
        let signed = secure_message.sign(&message).unwrap();

        let mut recv_pk = ma.public_key();
        let recv_pk = validate_public_key(recv_pk);
        if recv_pk.is_none() {
            panic!("could not validate the received public key");
        }
        let recv_pk = recv_pk.unwrap();

        let secure_message = SecureVerify::new(recv_pk);
        match secure_message.verify(&signed) {
            Ok(verified) => verified,
            Err(e) => panic!("verification error: {}", e),
        };
    }
}
