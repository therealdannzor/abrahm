// Common types being used during the consensus process

pub type View = u64;
pub type SequenceNumber = u64;
pub type Committer = String;
pub type ValidatorSet = std::vec::Vec<Committer>;
