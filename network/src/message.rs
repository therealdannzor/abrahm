#![allow(unused)]
use super::common::{
    cmp_message_with_signed_digest, create_p2p_message, parse_u8_to_enum, u8_to_ascii_decimal,
    usize_to_ascii_decimal, vec_u8_ascii_decimal_to_u8,
};
use bendy::decoding::{self, FromBencode, Object, ResultExt};
use bendy::encoding::{self, SingleItemEncoder, ToBencode};
use consensus::{
    messages_tp::{Commit, Prepare, Preprepare},
    request::Request,
    transition::{Transact, Transition},
};
use std::boxed::Box;
use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use swiss_knife::{
    hashed,
    helper::{generate_hash_from_input, hash_and_sign_message_digest},
};
use themis::{
    keys::{EcdsaPrivateKey, EcdsaPublicKey, PublicKey},
    secure_message::SecureSign,
};

#[derive(PartialEq, Copy, Clone)]
// The different type of message codes a peer send to one another
pub enum ConsensusCode {
    // Consensus messages
    TransactionRequest,
    PrePrepare,
    Prepare,
    Commit,
    ViewChange,
    NewView,
    Checkpoint,
}

pub enum HandshakeCode {
    // Handshakes after discovery
    Ping,
    Pong,
    AckPong,
}

impl fmt::Display for HandshakeCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HandshakeCode::Ping => write!(f, "ping"),
            HandshakeCode::Pong => write!(f, "pong"),
            HandshakeCode::AckPong => write!(f, "ack"),
        }
    }
}

impl fmt::Display for ConsensusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConsensusCode::TransactionRequest => write!(f, "txr"),
            ConsensusCode::PrePrepare => write!(f, "ppp"),
            ConsensusCode::Prepare => write!(f, "pre"),
            ConsensusCode::Commit => write!(f, "com"),
            ConsensusCode::ViewChange => write!(f, "chn"),
            ConsensusCode::NewView => write!(f, "new"),
            ConsensusCode::Checkpoint => write!(f, "cpt"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RawHandshake {
    // handshake sequence
    code: String,
    // local node public key
    id: String,
    // local node handshake port
    port: String,
}

impl RawHandshake {
    fn new(code: HandshakeCode, id: EcdsaPublicKey, port: String) -> Self {
        if port == "" {
            panic!("create handshake misses a port");
        }
        let code = code.to_string();
        let id = hex::encode(id).as_bytes().to_vec();
        let id = match std::str::from_utf8(&id.as_ref()) {
            Ok(s) => s.to_string(),
            Err(e) => panic!("themis key: this should not happen"),
        };
        Self { code, id, port }
    }

    pub fn code(&self) -> String {
        self.code.clone()
    }
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn port(&self) -> String {
        self.port.clone()
    }
}

#[derive(Debug)]
struct FullHandshake {
    // handshake in bencoded form
    handshake: Vec<u8>,
    // hashed and signed handshake
    signed: Vec<u8>,
}

impl FullHandshake {
    fn verify(&self, public_key: EcdsaPublicKey) -> bool {
        if self.handshake.len() == 0 || self.signed_len() == 0 {
            log::warn!("handshake missing field(s)");
            return false;
        }

        cmp_message_with_signed_digest(public_key, self.handshake.clone(), self.signed.clone())
    }

    fn parse(&self) -> Result<RawHandshake, decoding::Error> {
        Ok(RawHandshake::from_bencode(&self.handshake)?)
    }

    fn signed_len(&self) -> usize {
        self.signed.len()
    }

    fn plain_len(&self) -> usize {
        self.handshake.len()
    }

    fn signed_message(&self) -> Vec<u8> {
        self.signed.clone()
    }
}

#[derive(Clone)]
// Used for three-way handshakes after discovery
pub struct FixedHandshakes {
    // author_id is the identity creating the handshake messages
    author_id: EcdsaPublicKey,

    // handshakes
    ping: Vec<u8>,
    pong: Vec<u8>,
    ack: Vec<u8>,
}
impl FixedHandshakes {
    pub fn new(
        id: EcdsaPublicKey,
        port: String,
        secret_key: EcdsaPrivateKey,
    ) -> Result<Self, encoding::Error> {
        let ping = new_handshake(
            HandshakeCode::Ping,
            id.clone(),
            port.clone(),
            secret_key.clone(),
        )?;
        let pong = new_handshake(
            HandshakeCode::Pong,
            id.clone(),
            port.clone(),
            secret_key.clone(),
        )?;
        let ack = new_handshake(HandshakeCode::AckPong, id.clone(), port, secret_key)?;
        Ok(Self {
            author_id: id,
            ping,
            pong,
            ack,
        })
    }

    pub fn author_id(&self) -> EcdsaPublicKey {
        self.author_id.clone()
    }

    pub fn ping(&self) -> Vec<u8> {
        self.ping.clone()
    }
    pub fn pong(&self) -> Vec<u8> {
        self.pong.clone()
    }
    pub fn ack(&self) -> Vec<u8> {
        self.ack.clone()
    }
}

// new_handshake creates a new p2p handshake used to perform the three-way handshake.
// If it is successful, it is immediately ready to be sent over the network.
fn new_handshake(
    code: HandshakeCode,
    id: EcdsaPublicKey,
    port: String,
    secret_key: EcdsaPrivateKey,
) -> Result<Vec<u8>, encoding::Error> {
    let raw = RawHandshake::new(code, id.clone(), port);
    let handshake = raw.to_bencode()?;
    let signed = hash_and_sign_message_digest(secret_key, handshake.clone());
    let hs = FullHandshake { handshake, signed };
    let bencode = hs.to_bencode()?;
    Ok(bencode)
}

// from_handshake receives a p2p handshake from another, connected peer.
// If it is successful, it is a valid p2p handshake message and its content
// can be trusted to be authentic.
pub fn from_handshake(
    hs: Vec<u8>,
    other_peer_pk: EcdsaPublicKey,
) -> Result<RawHandshake, decoding::Error> {
    let full = FullHandshake::from_bencode(&hs)?;
    if !full.verify(other_peer_pk) {
        return Err(decoding::Error::missing_field(String::from_utf8_lossy(
            b"invalid message, check other peer public key",
        )));
    }
    full.parse()
}

impl FromBencode for FullHandshake {
    const EXPECTED_RECURSION_DEPTH: usize = RawHandshake::EXPECTED_RECURSION_DEPTH + 1;

    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        let mut handshake = None;
        let mut signed = None;
        let mut dict = object.try_into_dictionary()?;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"handshake", value) => {
                    handshake = Vec::<u8>::decode_bencode_object(value)
                        .context("handshake")
                        .map(Some)?;
                }
                (b"signed", value) => {
                    signed = Vec::<u8>::decode_bencode_object(value)
                        .context("signed")
                        .map(Some)?;
                }
                (unknown_field, _) => {
                    return Err(decoding::Error::unexpected_field(String::from_utf8_lossy(
                        unknown_field,
                    )));
                }
            }
        }

        let handshake = handshake.ok_or_else(|| decoding::Error::missing_field("handshake"))?;
        let signed = signed.ok_or_else(|| decoding::Error::missing_field("signed"))?;

        Ok(FullHandshake { handshake, signed })
    }
}

impl FromBencode for RawHandshake {
    const EXPECTED_RECURSION_DEPTH: usize = 1;

    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        let mut code = None;
        let mut id = None;
        let mut port = None;
        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"code", value) => {
                    code = String::decode_bencode_object(value)
                        .context("code")
                        .map(Some)?;
                }
                (b"id", value) => {
                    id = String::decode_bencode_object(value)
                        .context("id")
                        .map(Some)?;
                }
                (b"port", value) => {
                    port = String::decode_bencode_object(value)
                        .context("port")
                        .map(Some)?;
                }
                (unknown_field, _) => {
                    return Err(decoding::Error::unexpected_field(String::from_utf8_lossy(
                        unknown_field,
                    )));
                }
            }
        }

        let code = code.ok_or_else(|| decoding::Error::missing_field("code"))?;
        let id = id.ok_or_else(|| decoding::Error::missing_field("id"))?;
        let port = port.ok_or_else(|| decoding::Error::missing_field("port"))?;

        Ok(RawHandshake { code, id, port })
    }
}

impl ToBencode for FullHandshake {
    const MAX_DEPTH: usize = RawHandshake::MAX_DEPTH + 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"handshake", &self.handshake)?;
            e.emit_pair(b"signed", &self.signed)?;

            Ok(())
        })
    }
}

impl ToBencode for RawHandshake {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"code", &self.code)?;
            e.emit_pair(b"id", &self.id)?;
            e.emit_pair(b"port", &self.port)?;

            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct MessageWorker {
    public_key: EcdsaPublicKey,
    secret_key: EcdsaPrivateKey,
    peer_shortnames: HashMap<u8, EcdsaPublicKey>,
}
impl MessageWorker {
    pub fn new(
        peer_shortnames: HashMap<u8, EcdsaPublicKey>,
        secret_key: EcdsaPrivateKey,
        public_key: EcdsaPublicKey,
    ) -> Self {
        Self {
            public_key,
            secret_key,
            peer_shortnames,
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
    use crate::common::usize_to_ascii_decimal;
    use consensus::transition::{Transact, Transition};
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use swiss_knife::hashed;
    use swiss_knife::helper::generate_hash_from_input;
    use themis::keygen;
    use themis::secure_message::{SecureSign, SecureVerify};
    use tokio_test::{assert_err, assert_ok};

    #[test]
    fn create_parse_validate_p2p_three_way_handshake_messages() {
        let ping = HandshakeCode::Ping;
        let pong = HandshakeCode::Pong;
        let ack = HandshakeCode::AckPong;
        let (a_sk, a_pk) = keygen::gen_ec_key_pair().split();
        let (b_sk, b_pk) = keygen::gen_ec_key_pair().split();
        let a_port = "8080".to_string();
        let b_port = "8081".to_string();

        let ping_message = new_handshake(ping, a_pk.clone(), a_port.clone(), a_sk.clone());
        assert_ok!(ping_message.clone());
        let ping_message = ping_message.unwrap();
        let parsed_ping = from_handshake(ping_message.clone(), a_pk.clone());
        assert_ok!(parsed_ping.clone());
        let parsed_ping = parsed_ping.unwrap();
        assert_eq!(parsed_ping.code, "ping".to_string());
        assert_eq!(parsed_ping.port, a_port);
        let ping_parse_err = from_handshake(ping_message, b_pk.clone());
        assert_err!(ping_parse_err);

        let pong_message = new_handshake(pong, b_pk.clone(), b_port.clone(), b_sk);
        assert_ok!(pong_message.clone());
        let pong_message = pong_message.unwrap();
        let parsed_pong = from_handshake(pong_message.clone(), b_pk.clone());
        assert_ok!(parsed_pong.clone());
        let parsed_pong = parsed_pong.unwrap();
        assert_eq!(parsed_pong.code, "pong".to_string());
        assert_eq!(parsed_pong.port, b_port);
        let pong_parse_err = from_handshake(pong_message, a_pk.clone());
        assert_err!(pong_parse_err);

        let ack_message = new_handshake(ack, a_pk.clone(), a_port.clone(), a_sk.clone());
        assert_ok!(ack_message.clone());
        let ack_message = ack_message.unwrap();
        let parsed_ack = from_handshake(ack_message.clone(), a_pk.clone());
        assert_ok!(parsed_ack.clone());
        let parsed_ack = parsed_ack.unwrap();
        assert_eq!(parsed_ack.code, "ack".to_string());
        assert_eq!(parsed_ack.port, a_port);
        let ack_parse_err = from_handshake(ack_message, b_pk.clone());
        assert_err!(ack_parse_err);
    }

    #[test]
    fn outgoing_message_serialize_request_struct_and_verify_authenticity() {
        let (sk, pk) = keygen::gen_ec_key_pair().split();
        let (_, bob_pk) = keygen::gen_ec_key_pair().split();

        let mut peer_map: HashMap<u8, EcdsaPublicKey> = HashMap::new();
        peer_map.insert(49 /* corresponds to 1 */, pk.clone());
        peer_map.insert(2, bob_pk.clone());

        let mut mw = MessageWorker::new(peer_map, sk.clone(), pk.clone());

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
        let (other_sk, other_pk) = keygen::gen_ec_key_pair().split();
        let mut peer_map: HashMap<u8, EcdsaPublicKey> = HashMap::new();
        peer_map.insert(2, other_pk);
        peer_map.insert(8, first_pk.clone());
        let mut mw = MessageWorker::new(peer_map, first_sk, first_pk.clone());

        let too_short_message = vec![60, 60, 60];
        let actual = mw.validate_received(too_short_message);
        // check that we receive error for incorrect message length
        assert_err!(actual);

        let good_enough_len = vec![1; 152];
        let actual = mw.validate_received(good_enough_len);
        // check that we receive error for missing entry of peer public key (inserted id=2 but we
        // have id=1)
        assert_err!(actual);

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
        let mut peer_map: HashMap<u8, EcdsaPublicKey> = HashMap::new();
        peer_map.insert(1, pk.clone());
        let mut mw = MessageWorker::new(peer_map, sk, pk.clone());

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
