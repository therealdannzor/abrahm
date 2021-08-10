#![allow(unused)]

use super::common::usize_to_ascii_decimal;
use super::message::MessageWorker;
use super::node_actor::{ActorMessage, NodeActor};
use crate::consensus::messages_tp::{Commit, Prepare, Preprepare};
use crate::consensus::request::Request;
use std::io::ErrorKind;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::mpsc as tokio_mpsc;

// Net handles the blockchain network communication. It does this through assembly of
// consensus messages and dispatches them to external peers.
pub struct Net {
    // Message IO
    pub message_worker: MessageWorker,
    // Node communication IO
    pub node: NodeActor,
}

impl Net {
    pub fn new(
        stream_cap: usize,
        public_key: EcdsaPublicKey,
        secret_key: EcdsaPrivateKey,
        receiver: tokio_mpsc::Receiver<ActorMessage>,
    ) -> Self {
        Self {
            message_worker: MessageWorker::new(secret_key, public_key.clone()),
            node: NodeActor::new(public_key, stream_cap, receiver),
        }
    }

    pub fn broadcast_data(self, short_identifier: u8, message: Vec<u8>) -> std::io::Result<()> {
        let res = self.node.send(message);
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        Ok(())
    }

    // crunch_message consumes the oldest unprocessed message stored in the mailbox
    pub fn crunch_message(self) -> Option<Vec<u8>> {
        let res = self.node.get_next_message();
        if res.is_none() {
            return None;
        } else {
            res
        }
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
            let signed = self.message_worker.sign_message_digest(&ser.clone());
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
            let signed = self.message_worker.sign_message_digest(&ser.clone());
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
            let signed = self.message_worker.sign_message_digest(&ser.clone());
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
            let signed = self.message_worker.sign_message_digest(&ser.clone());
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

fn check_id_length(short_identifier: u8) -> Result<(), std::io::Error> {
    if short_identifier < 48 || short_identifier > 57 {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            "must be digit between 48 and 57 (0-9)",
        ));
    }
    Ok(())
}
