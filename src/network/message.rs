#![allow(unused)]
use crate::swiss_knife::helper::hash_and_sign_message_digest;
use std::boxed::Box;
use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey, PublicKey};
use themis::secure_message::SecureSign;

use super::common::{
    cmp_message_with_signed_digest, parse_u8_to_enum, u8_to_ascii_decimal, usize_to_ascii_decimal,
    vec_u8_ascii_decimal_to_u8,
};
use crate::consensus::messages_tp::{Commit, Prepare, Preprepare};
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

    pub fn insert_peer(&mut self, key: u8, value: EcdsaPublicKey) {
        self.peer_shortnames.insert(key, value);
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    // The message structure is as follows:
    //
    // +-----------------------------------------------------------+
    // | Consensus round  | Peer ID       | Payload length         |
    // | (1 character)    | (1 character) | (3 characters)         |
    // |-----------------------------------------------------------+
    // | Serialized message    | Signed message digest             |
    // | (length varies)       | (241 - 243 characters)            |
    // +-----------------------------------------------------------+
    // * Consensus round:
    //   0 (request / txs), 1 (preprepare), 2 (prepare), 3 (commit),
    //   4 (view change), 5 (new view), and 6 (checkpoint)
    // * Peer identifier: 1 character (digit)
    // * Length of payload: 3 characters
    // * Serialized message: varying length; plain text
    // * Signed message digest: the rest of the message (TODO: understand why its length
    //   differs with ± 2 chars)
    pub fn validate_received(&self, message: Vec<u8>) -> Result<(), std::io::Error> {
        if message.len() < 152 {
            return Err(validation_error("recv message length less than expected"));
        }

        let consensus_round = message[0];
        if consensus_round > 6 {
            return Err(validation_error("invalid consensus message round"));
        }
        let targ_short_id = message[1];
        let targ_pub_key = match self.peer_shortnames.get(&targ_short_id) {
            Some(k) => k,
            None => {
                return Err(validation_error("missing public key from other peer"));
            }
        };

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

        Ok(())
    }

    pub fn create_request_message(
        &self,
        short_identifier: u8,
        payload: Request,
    ) -> Result<Vec<u8>, std::io::Error> {
        let msg = self.create_consensus_message(short_identifier, Some(payload), None, None, None);
        if msg.is_err() {
            return Err(msg.err().unwrap());
        }
        Ok(msg.unwrap())
    }

    pub fn create_preprepare_message(
        &self,
        short_identifier: u8,
        payload: Preprepare,
    ) -> Result<Vec<u8>, std::io::Error> {
        let msg = self.create_consensus_message(short_identifier, None, Some(payload), None, None);
        if msg.is_err() {
            return Err(msg.err().unwrap());
        }
        Ok(msg.unwrap())
    }

    pub fn create_prepare_message(
        &self,
        short_identifier: u8,
        payload: Prepare,
    ) -> Result<Vec<u8>, std::io::Error> {
        let msg = self.create_consensus_message(short_identifier, None, None, Some(payload), None);
        if msg.is_err() {
            return Err(msg.err().unwrap());
        }
        Ok(msg.unwrap())
    }

    pub fn create_commit_message(
        &self,
        short_identifier: u8,
        payload: Commit,
    ) -> Result<Vec<u8>, std::io::Error> {
        let msg = self.create_consensus_message(short_identifier, None, None, None, Some(payload));
        if msg.is_err() {
            return Err(msg.err().unwrap());
        }
        Ok(msg.unwrap())
    }

    fn create_consensus_message(
        &self,
        short_identifier: u8,
        request: Option<Request>,
        preprepare: Option<Preprepare>,
        prepare: Option<Prepare>,
        commit: Option<Commit>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let ser_error = std::io::Error::new(ErrorKind::InvalidData, "serialize error");
        check_id_length(short_identifier)?;
        let mut msg: Vec<u8> = Vec::new();
        msg.push(short_identifier);
        if request.is_some() {
            msg.push(48);
            let ser = serde_json::to_string(&request.unwrap());
            if ser.is_err() {
                return Err(ser_error);
            }
            let ser = ser.unwrap();
            let ser_len = usize_to_ascii_decimal(ser.len());
            msg.extend(ser_len);
            msg.extend(ser.as_bytes().to_vec());
            let signed =
                hash_and_sign_message_digest(self.secret_key.clone(), ser.as_bytes().to_vec());
            msg.extend(signed);
        } else if preprepare.is_some() {
            msg.push(49);
            let ser = serde_json::to_string(&preprepare.unwrap());
            if ser.is_err() {
                return Err(ser_error);
            }
            let ser = ser.unwrap();
            let ser_len = usize_to_ascii_decimal(ser.len());
            msg.extend(ser_len);
            msg.extend(ser.as_bytes().to_vec());
            let signed =
                hash_and_sign_message_digest(self.secret_key.clone(), ser.as_bytes().to_vec());
            msg.extend(signed);
        } else if prepare.is_some() {
            msg.push(50);
            let ser = serde_json::to_string(&prepare.unwrap());
            if ser.is_err() {
                return Err(ser_error);
            }
            let ser = ser.unwrap();
            let ser_len = usize_to_ascii_decimal(ser.len());
            msg.extend(ser_len);
            msg.extend(ser.as_bytes().to_vec());
            let signed =
                hash_and_sign_message_digest(self.secret_key.clone(), ser.as_bytes().to_vec());
            msg.extend(signed);
        } else if commit.is_some() {
            msg.push(51);
            let ser = serde_json::to_string(&commit.unwrap());
            if ser.is_err() {
                return Err(ser_error);
            }
            let ser = ser.unwrap();
            let ser_len = usize_to_ascii_decimal(ser.len());
            msg.extend(ser_len);
            msg.extend(ser.as_bytes().to_vec());
            let signed =
                hash_and_sign_message_digest(self.secret_key.clone(), ser.as_bytes().to_vec());
            msg.extend(signed);
        } else {
            return Err(std::io::Error::new(
                ErrorKind::NotFound,
                "missing consensus proposal",
            ));
        }

        Ok(msg)
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

fn validation_error(text: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Other,
        MessageValidationError(text.into()),
    )
}

pub fn validate_public_key(key: &[u8]) -> Option<PublicKey> {
    match PublicKey::try_from_slice(key) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

fn create_request_type(account: &str, from: u8, to: u8, amount: u32) -> Request {
    let next_transition =
        Transition::new(String::from("0x"), vec![Transact::new(from, to, amount)]);
    Request::new(next_transition, "id")
}

fn check_id_length(short_identifier: u8) -> Result<(), std::io::Error> {
    if short_identifier < 48 || short_identifier > 57 {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "must be digit between 48 and 57 (0-9)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::transition::{Transact, Transition};
    use crate::hashed;
    use crate::network::common::usize_to_ascii_decimal;
    use crate::swiss_knife::helper::generate_hash_from_input;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use std::convert::TryFrom;
    use themis::keygen;
    use themis::secure_message::{SecureSign, SecureVerify};
    use tokio_test::{assert_err, assert_ok};

    #[test]
    fn outgoing_message_serialize_request_struct_and_verify_authenticity() {
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk.clone(), pk.clone());
        mw.insert_peer(49 /* corresponds to 1 */, pk.clone());
        let (_, bob_pk) = keygen::gen_ec_key_pair().split();
        mw.insert_peer(2, bob_pk.clone());

        let request = create_request_type("0x", 1, 2, 1);

        // 1st component: a single byte representing message type
        let is_consensus = u8::from(1);

        // 2nd component: peer which sends the signed message
        let peer_id = u8_to_ascii_decimal(u8::from(1));

        // 4th component: the serialized message
        let serialized = serde_json::to_string(&request);
        if serialized.is_err() {
            panic!("error serializing: {:?}", serialized.unwrap());
        }
        let serialized = serialized.unwrap();

        // 3rd component: the length of the message
        let message_length = usize_to_ascii_decimal(serialized.len());

        // prepare to sign the request
        let signed_request =
            hash_and_sign_message_digest(sk.clone(), serialized.as_bytes().to_vec());

        // add all components to a complete message
        let mut full_message = Vec::new();
        full_message.push(is_consensus);
        full_message.extend(peer_id);
        full_message.extend(message_length);
        full_message.extend(serialized.as_bytes().to_vec());
        full_message.extend(signed_request);
        let result = mw.validate_received(full_message);
        assert_ok!(result);
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
        let payload = vec![2; 160]; // 160 corresponds to [49, 54, 48]
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8, 2, 65 /* 'A' (invalid) */, 54, 48];
        message.extend(payload.clone());
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![1, 2, 49, 54, 48];
        let err_payload = vec![255; 200]; // choose non utf-8 payload
        message.extend(err_payload);
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![8 /* invalid consensus flag */, 2, 49, 54, 48];
        message.extend(payload.clone()); // choose any other payload than a signed message by peer 8's secret key
        let actual = mw.validate_received(message);
        assert_err!(actual);

        let mut message = vec![1, 2, 49, 54, 48];
        message.extend(payload.clone()); // not signed properly
        let actual = mw.validate_received(message);
        assert_err!(actual);
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

    #[ignore]
    #[test]
    pub fn sign_and_decrypt_consensus_message() {
        // Setup the client signation and known information about a supposed foreign peer
        // (in this case we use the client's public key as the foreign peer's identity for brevity)
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let mut mw = MessageWorker::new(sk.clone(), pk.clone());
        mw.insert_peer(1, pk.clone());

        // Sign a secret message with shortest possible length
        let signed = hash_and_sign_message_digest(sk.clone(), vec![49]);
        let sign_len = usize_to_ascii_decimal(signed.len());
        // Construct the complete message as passed over TCP:
        // Index 0:        Consensus phase
        // Index 1:        Peer ID
        // Index 2 to 4:   Length (L) of payload
        // Index 5 to 5+L: Payload
        //
        // 48 = digit 0 in ASCII decimal
        // 49 = digit 1 in ASCII decimal
        let mut msg = vec![1, 1, 48, 48, 49, 49];
        // After appending the signed message:
        // From index 5+L+1 to the end : The signed message
        msg.extend(signed);

        // Returns true if the message we have constructed is authentic and non-tampered with
        let result = mw.validate_received(msg);
        assert_ok!(result);
    }
}
