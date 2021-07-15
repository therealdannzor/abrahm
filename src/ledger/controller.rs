#![allow(unused)]
use super::state_db::{KeyValueIO, StateDB};
use std::{collections::HashMap, io::ErrorKind};
use themis::keys::EcdsaPublicKey;

// LedgerStateController verifies if a transaction (or request thereof) is allowed to be executed on the
// ledger. Allowed in this sense means that the sender can afford to send the amount requested
// and that it is able to cover any additional costs. It is also able to calculate fees and carry
// out the actual transaction on the state database.
pub struct LedgerStateController {
    db: StateDB,
    cache: HashMap<EcdsaPublicKey, u32>,
}
impl LedgerStateController {
    pub fn new(db: StateDB) -> Self {
        Self {
            db,
            cache: HashMap::new(),
        }
    }

    pub fn is_valid_amount(&self, account: EcdsaPublicKey, amount: i16) -> bool {
        let bal = db_get(&self.db, account.clone());
        if bal.is_err() {
            return false;
        }
        let bal = vec_u8_ascii_code_to_int(bal.unwrap());
        let fee = calculate_fee(bal as u16) as u32;
        if amount as u32 + fee <= bal {
            return true;
        }
        false
    }

    // add adds a value to an account balance. For convenience this can be used with both positive
    // and negative values to represent additions and subtractions to an account, respectively.
    pub fn add(mut self, account: EcdsaPublicKey, amount: i16) -> Result<(), std::io::Error> {
        if !self.is_valid_amount(account.clone(), amount) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "invalid amount",
            ));
        }
        let bal = db_get(&self.db, account.clone());
        if bal.is_err() {
            return Err(bal.err().unwrap());
        }
        let bal = vec_u8_ascii_code_to_int(bal.unwrap());
        if (bal + amount as u32) > u32::MAX {
            return Err(std::io::Error::new(ErrorKind::Other, "overflow balance"));
        }
        let updated_bal = bal + amount as u32;
        self.db.put(account.clone(), &updated_bal.to_string());
        self.cache.insert(account, updated_bal);

        Ok(())
    }

    // balance returns the balance of target account (default: 0)
    pub fn balance(&self, account: EcdsaPublicKey) -> u32 {
        let bal = db_get(&self.db, account);
        if bal.is_err() {
            return 0;
        }
        vec_u8_ascii_code_to_int(bal.unwrap())
    }

    // TODO: refine later for a more progressive fee rate
    pub fn extract_fee(
        mut self,
        account: EcdsaPublicKey,
        amount: u16,
    ) -> Result<(), std::io::Error> {
        let fee = calculate_fee(amount);
        match &self.add(account, (fee * (-1.0)) as i16) {
            Ok(num) => Ok(()),
            Err(e) => return Err(std::io::Error::new(ErrorKind::Other, "extract fee error")),
        }
    }
}

fn db_get(db: &StateDB, account: EcdsaPublicKey) -> std::result::Result<Vec<u8>, std::io::Error> {
    let res = match db.get_value(account.clone()) {
        Ok(num) => return Ok(num),
        Err(e) => return Err(e),
    };
}

fn vec_u8_ascii_code_to_int(input: Vec<u8>) -> u32 {
    let s = String::from_utf8(input).expect("invalid utf-8");
    s.parse::<u32>().unwrap()
}

// calculate_fee calculates 5% of the transfer amount, rounded up, as fee
pub fn calculate_fee(amount: u16) -> f64 {
    (((amount as f64) / 100f64) * 5f64).ceil()
}
