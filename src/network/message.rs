#![allow(unused)]
use std::boxed::Box;
use std::collections::HashMap;
use std::fmt;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey, PublicKey};
use themis::secure_message::SecureSign;

use super::common::{
    cmp_message_with_signed_digest, parse_u8_to_enum, u8_to_ascii_decimal,
    vec_u8_ascii_decimal_to_u8,
};
use crate::consensus::request::Request;
use crate::consensus::transition::{Transact, Transition};
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
    pub fn validate_received(&self, message: Vec<u8>) -> Result<bool, Box<dyn std::error::Error>> {
        if message.len() < 152 {
            return Err(validation_error("length less than expected"));
        }
        let targ_short_id = message[0];
        let targ_pub_key = self.peer_shortnames.get(&targ_short_id);
        if targ_pub_key.is_none() {
            return Err(validation_error("missing public key from other peer"));
        }

        let targ_pub_key = targ_pub_key.unwrap();
        let consensus_round_type = message[1];
        if consensus_round_type > 5 {
            return Err(validation_error("invalid consensus message flag"));
        }

        let consensus_round = parse_u8_to_enum(consensus_round_type);

        let mut payload_len: Vec<u8> = Vec::new();
        for i in 0..3 {
            let ch = message[2 + i] as char;
            let dig = ch.to_digit(10);
            if dig.is_some() {
                payload_len.push(dig.unwrap() as u8);
            } else {
                return Err(validation_error(
                    "invalid digit representing message length",
                ));
            }
        }

        let payload_len = vec_u8_ascii_decimal_to_u8(payload_len) as usize;
        let payload = &message[5..payload_len + 5];
        let try_utf8 = std::str::from_utf8(payload);
        if try_utf8.is_err() {
            return Err(validation_error("could not convert payload to utf-8"));
        }
        let payload: Vec<u8> = payload.to_vec();

        let claimed_signed = message[payload_len + 5..].to_vec();
        if !cmp_message_with_signed_digest(targ_pub_key.clone(), payload, claimed_signed) {
            return Err(validation_error("message authenticity mismatch"));
        }

        Ok(true)
    }
}

#[derive(Debug)]
struct MessageValidationError(String);
impl fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "message validation error: {}", self.0)
    }
}
impl std::error::Error for MessageValidationError {}

fn validation_error(text: &str) -> Box<dyn std::error::Error + 'static> {
    Box::new(MessageValidationError(text.into()))
}

pub fn validate_public_key(key: &[u8]) -> Option<PublicKey> {
    match PublicKey::try_from_slice(key) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

fn create_request_type(
    account: &str,
    from: EcdsaPublicKey,
    to: EcdsaPublicKey,
    amount: i32,
) -> Request {
    let next_transition =
        Transition::new(String::from("0x"), vec![Transact::new(from, to, amount)]);
    Request::new(next_transition, "id")
}

mod tests {
    use super::*;
    use crate::consensus::testcommons::generate_keys;
    use crate::hashed;
    use crate::swiss_knife::helper::generate_hash_from_input;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use std::convert::TryFrom;
    use themis::keygen;
    use themis::keys::EcdsaPublicKey;
    use themis::secure_message::{SecureSign, SecureVerify};
    use tokio_test::assert_err;

    #[test]
    pub fn sign_and_decrypt_ultra_short_message() {
        // Setup the client signation and known information about a supposed foreign peer
        // (in this case we use the client's public key as the foreign peer's identity for brevity)
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk, pk.clone());
        mw.insert_peer(1, pk.clone());

        // Sign a secret message with shortest possible length
        let signed = mw.sign_message_digest(&String::from("1"));
        // Construct the complete message as passed over TCP:
        // Index 0:        Peer ID
        // Index 1:        Consensus message type
        // Index 2 to 4:   Length (L) of payload
        // Index 5 to 5+L: Payload
        //
        // 48 = digit 0 in ASCII decimal
        // 49 = digit 1 in ASCII decimal
        let mut msg = vec![1, 0, 48, 48, 49, 49];
        // After appending the signed message:
        // From index 5+L+1 to the end : The signed message
        msg.extend(signed);

        // Returns true if the message we have constructed is authentic and non-tampered with
        let result = mw.validate_received(msg);
        if result.is_err() {
            panic!("{:?}", result.err());
        }
        assert!(true);
    }

    #[test]
    fn outgoing_message_serialize_request_struct_and_verify_authenticity() {
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk, pk.clone());
        mw.insert_peer(1, pk.clone());

        let bob_pk = generate_keys(1);
        let request = create_request_type("0x", pk, bob_pk[0].clone(), 1);

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

        // this is the u8 size of the length, we need to split this up into individual units ascii
        // coded, three digits in total
        let message_length = message_length.unwrap();
        let message_length = u8_to_ascii_decimal(message_length);

        // prepare to sign the request
        let signed_request = mw.sign_message_digest(&serialized.as_ref().unwrap());

        // add all components to a complete message
        let mut full_message = Vec::new();
        full_message.push(target_id);
        full_message.push(type_flag);
        full_message.extend(message_length);
        full_message.extend(serialized.unwrap().as_bytes().to_vec());
        full_message.extend(signed_request);
        let result = mw.validate_received(full_message);
        if result.is_err() {
            panic!("{:?}", result.err());
        }
        assert!(result.unwrap())
    }

    #[test]
    fn go_through_all_error_paths_for_message_cmp_method() {
        let (first_sk, first_pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(first_sk, first_pk.clone());

        let too_short_message = vec![60, 60, 60];
        let actual = mw.validate_received(too_short_message);
        // check that we receive error for incorrect message length
        assert_err!(actual);

        let (other_sk, other_pk) = keygen::gen_ec_key_pair().split();
        let good_enough_len = vec![1; 152];
        mw.insert_peer(2, other_pk);
        let actual = mw.validate_received(good_enough_len);
        // check that we receive error for missing entry of peer public key (inserted id=2 but we
        // have id=1)
        assert_err!(actual);

        mw.insert_peer(8, first_pk.clone());
        let mut message = vec![
            8,  /* peer id */
            9,  /* incorrect consensus val */
            49, /* 1*/
            54, /* 6 */
            48, /* 0 */
        ];
        let payload = vec![2; 160];
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8, 1, 65 /* 'A' (invalid) */, 54, 48];
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8, 1, 49, 54, 48];
        let err_payload = vec![255; 200]; // choose non utf-8 payload
        message.extend(err_payload);
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8, 1, 49, 54, 48];
        message.extend(payload.clone()); // choose any other payload than a signed message by peer 8's secret key
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8, 1, 49, 54, 48];
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
    }

    #[test]
    fn edge_cases() {
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk, pk.clone());
        mw.insert_peer(1, pk.clone());

        let mut message = vec![1, 1];
        let payload = vec![3; 500]; // too long payload
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![1, 1, 49, 54, 48]; // lie about message length
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);
    }
}
