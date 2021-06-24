#![allow(unused)]

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use themis::keygen;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey, PublicKey};
use themis::secure_message::SecureSign;

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
}
impl MessageSanitizer {
    pub fn new(remote_public_key: PublicKey) -> Self {
        Self { remote_public_key }
    }
}

// TODO: formalize a message structure protocol:
// * public key information / identity (last 40 characters of the public key hash);
// * consensus message flag (most likely able to store in 1 byte);
// * message digest (with Sha256 -> 64 characters);
// * and the seralized message (payload)
pub fn validate_message_length(mut slice: &[u8], len: usize) -> bool {
    if slice.len() != len {
        return false;
    }

    true
}

pub fn validate_public_key(key: &[u8]) -> Option<PublicKey> {
    match PublicKey::try_from_slice(key) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
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
    fn abc() {
        let (other_peer_sk, other_peer_pk) = keygen::gen_ec_key_pair().split();
        let next_transition = Transition::new("0x", vec![Transact::new("Alice", "Bob", 1)]);
        let request = Request::new(next_transition, "id");
        let serialized = serde_json::to_string(&request);
        if serialized.is_err() {
            panic!("error serializing: {}", serialized.unwrap());
        }
        println!("serialized: {:?}", serialized.as_ref().clone().unwrap());
        let d_m = hashed!(&serialized.unwrap());
        println!("hashed ser: {}", d_m);
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
