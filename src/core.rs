use crate::state_db::KeyValueIO;
use crate::state_db::StateDB;
use crate::txn_pool::create_new_tx_pool;
use crate::txn_pool::TxPool;

#[allow(dead_code)]
pub struct Blockchain {
    pool: TxPool,
    account_db: StateDB,
}

const EMPTY_ACC: &str = "0x";

impl Blockchain {
    #[allow(dead_code)]
    pub fn new(account_db_path: &str) -> Self {
        Self {
            pool: create_new_tx_pool(EMPTY_ACC, true),
            account_db: StateDB::new(account_db_path),
        }
    }
}
