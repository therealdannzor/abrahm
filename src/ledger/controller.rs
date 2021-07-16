#![allow(unused)]
use super::state_db::{KeyValueIO, StateDB};
use std::{collections::HashMap, io::ErrorKind};
use themis::keys::EcdsaPublicKey;

// LedgerStateController verifies if a transaction (or request thereof) is allowed to be executed on the
// ledger. Allowed in this sense means that the sender can afford to send the amount requested
// and that it is able to cover any additional costs. It is also able to calculate fees and carry
// out the actual transaction on the state database.
pub struct LedgerStateController {
    id: EcdsaPublicKey,
    db: StateDB,
    cache: HashMap<EcdsaPublicKey, u32>,
}
impl LedgerStateController {
    pub fn new(id: EcdsaPublicKey, db: StateDB) -> Self {
        Self {
            id,
            db,
            cache: HashMap::new(),
        }
    }

    // fund mints a balance for a target account
    pub fn fund(&mut self, account: EcdsaPublicKey, amount: u32) {
        self.db.put(account.clone(), &amount.to_string());
        self.cache.insert(account, amount);
    }

    // add adds a value to an account balance
    pub fn add(&mut self, account: EcdsaPublicKey, amount: i16) -> Result<(), std::io::Error> {
        let val = validate_transaction(&self.db, self.id.clone(), account.clone(), amount);
        if val.is_err() {
            return Err(val.err().unwrap());
        }

        let bal = db_get(&self.db, account.clone());
        if bal.is_err() {
            return Err(bal.err().unwrap());
        }
        let bal = vec_u8_ascii_code_to_int(bal.unwrap());
        if amount > 0 && (bal + amount as u32) > u32::MAX {
            return Err(std::io::Error::new(ErrorKind::Other, "overflow balance"));
        }
        let updated_bal = bal + amount as u32;
        self.db.put(account.clone(), &updated_bal.to_string());
        self.cache.insert(account, updated_bal);

        Ok(())
    }

    // sub substracts a value to an account balance
    pub fn sub(&mut self, account: EcdsaPublicKey, amount: u16) -> Result<(), std::io::Error> {
        let val = validate_transaction(&self.db, self.id.clone(), account.clone(), amount as i16);
        if val.is_err() {
            return Err(val.err().unwrap());
        }
        let bal = db_get(&self.db, account.clone());
        if bal.is_err() {
            return Err(bal.err().unwrap());
        }
        let amount = amount as u32;
        let bal = vec_u8_ascii_code_to_int(bal.unwrap());
        if bal < amount {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "underflow balance",
            ));
        }
        let updated_bal = bal - amount;
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

fn validate_transaction(
    db: &StateDB,
    sender: EcdsaPublicKey,
    recipient: EcdsaPublicKey,
    amount: i16,
) -> Result<(), std::io::Error> {
    if sender == recipient {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "cannot send to oneself",
        ));
    } else if !is_valid_amount(db, sender, amount) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid amount",
        ));
    }
    Ok(())
}

fn db_get(db: &StateDB, account: EcdsaPublicKey) -> std::result::Result<Vec<u8>, std::io::Error> {
    let res = match db.get_value(account.clone()) {
        Ok(num) => return Ok(num),
        Err(e) => return Err(e),
    };
}

pub fn is_valid_amount(db: &StateDB, account: EcdsaPublicKey, amount: i16) -> bool {
    let bal = db_get(&db, account.clone());
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

fn vec_u8_ascii_code_to_int(input: Vec<u8>) -> u32 {
    let s = String::from_utf8(input).expect("invalid utf-8");
    let s = s.parse::<u32>();
    if s.is_err() {
        panic!("error when parsing: {:?}", s.err().unwrap());
    }
    s.unwrap()
}

// calculate_fee calculates 5% of the transfer amount, rounded up, as fee
pub fn calculate_fee(amount: u16) -> f64 {
    (((amount as f64) / 100f64) * 5f64).ceil()
}

mod tests {
    use super::*;
    use themis::{keygen::gen_ec_key_pair, keys::EcdsaPublicKey};
    use tokio_test::assert_ok;

    fn setup() -> (LedgerStateController, EcdsaPublicKey) {
        let pk = pub_key();
        let mut path: String = env!("CARGO_MANIFEST_DIR", "missing cargo manifest").to_string();
        path.push_str("/test");
        let c = LedgerStateController::new(pk.clone(), StateDB::new(&path));
        (c, pk.clone())
    }

    fn pub_key() -> EcdsaPublicKey {
        let (_, pk) = gen_ec_key_pair().split();
        pk
    }

    #[test]
    fn fund_and_defund() {
        let (mut c, pk) = setup();

        let result = c.add(pk.clone(), 100);
        assert_ok!(result);
        let bal = c.balance(pk.clone());
        assert_eq!(bal, 100);
    }
}
