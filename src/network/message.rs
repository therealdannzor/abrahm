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

pub struct MessageAssembler {
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
}
impl MessageAssembler {
    pub fn new(secret_key: EcdsaPrivateKey, public_key: EcdsaPublicKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref().clone()
    }
}

pub struct MessageSanitizer {
    remote_public_key: PublicKey,
    peer_shortnames: HashMap<u8, EcdsaPublicKey>,
}
impl MessageSanitizer {
    pub fn new(remote_public_key: PublicKey, peer_shortnames: HashMap<u8, EcdsaPublicKey>) -> Self {
        Self {
            remote_public_key,
            peer_shortnames,
        }
    }
}

// The message structure is as follows:
//
// * identity (1 character, a single digit identifier mapped to a public key)
// * message flag (1 character, covers both transaction and consensus);
// * message length flag (3 characters)
// * serialized message (varying length, indicated by previous length flag)
// * length of the signed message digest (because it differs with ± 2 chars, TODO: investigate!)
// * signed message digest
pub fn validate_assembled_message() -> bool {
    true
}

pub fn validate_public_key(key: &[u8]) -> Option<PublicKey> {
    match PublicKey::try_from_slice(key) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

pub fn sign_message_digest(secret_key: EcdsaPrivateKey, message: &str) -> Vec<u8> {
    let m_d = hashed!(message);
    let sec_message = SecureSign::new(secret_key);
    let sign_m_d = match sec_message.sign(&m_d) {
        Ok(m) => m,
        Err(e) => panic!("failed to sign message: {:?}", e),
    };
    sign_m_d
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

    fn create_request_type(account: &str, from: &str, to: &str, amount: i32) -> Request {
        let next_transition = Transition::new("0x", vec![Transact::new(from, to, amount)]);
        Request::new(next_transition, "id")
    }

    #[test]
    fn abc() {
        let (other_peer_sk, other_peer_pk) = keygen::gen_ec_key_pair().split();

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
        let signed_request =
            sign_message_digest(other_peer_sk, &hashed!(&serialized.as_ref().unwrap()));

        // add all components to a complete message
        let mut full_message = Vec::new();
        full_message.push(target_id);
        full_message.push(type_flag);
        full_message.push(message_length);
        full_message.extend(serialized.unwrap().as_bytes().to_vec());
        full_message.extend(signed_request);
        println!("length: {}", full_message.len());
    }

    #[test]
    fn xyz() {
        let (sk, mut pk) = keygen::gen_ec_key_pair().split();
        let mut ma = MessageAssembler::new(sk, pk);

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

        println!("Secure message: {:?}", secure_message);
    }
}
