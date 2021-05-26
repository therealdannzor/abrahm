use super::engine::{State, M};
use crate::{hashed, swiss_knife::helper::generate_hash_from_input};
use std::collections::HashMap;

// Common types being used during the consensus process
pub type View = u64;
pub type SequenceNumber = u64;
pub type Committer = String;
pub type ValidatorSet = std::vec::Vec<Committer>;

// TODO: proper signing for each peer because as it stands now, it is possible
// for replicas to masquerade one another
pub fn digest_m(phase: State, i: String, v: View, n: SequenceNumber) -> String {
    let mut to_hash = "".to_string();
    to_hash.push_str(&phase.into_inner().to_string());
    to_hash.push_str(&i);
    to_hash.push_str(&v.to_string());
    to_hash.push_str(&n.to_string());
    hashed!(&to_hash.to_string())
}

// Filters all messages of the same view. We leave the input vector untouched.
pub fn filter_view(needle: View, haystack: Vec<M>) -> Vec<M> {
    let mut result: Vec<M> = Vec::new();
    for m in haystack.iter().clone() {
        if m.v == needle {
            result.push(m.clone());
        }
    }
    result
}

// Filters all messages in the same consensus phase. Does not modify input.
pub fn filter_phase(needle: State, haystack: Vec<M>) -> Vec<M> {
    let mut result: Vec<M> = Vec::new();
    for m in haystack.iter().clone() {
        if m.phase == needle {
            result.push(m.clone());
        }
    }
    result
}

// Returns the data payload (embedded in M) in which there have been most votes for
// and the amount of votes for it.
pub fn count_votes(haystack: Vec<M>) -> (String, usize) {
    let mut most_popular = String::from("");
    let mut most_amount = 0;
    let mut map = HashMap::new();
    for m in haystack.iter() {
        let c = map.entry(m.d.clone()).or_insert(0);
        *c += 1;
        if *c > most_amount {
            most_popular = m.d.clone();
            most_amount = *c;
        }
    }

    (most_popular, most_amount)
}

// Returns true if `haystack` contains equivalent `m` messages, else false
pub fn same_message_in_set(m: Option<M>, haystack: Vec<M>) -> bool {
    if m.is_none() {
        false;
    }

    for n in haystack.iter().clone() {
        if m.clone().unwrap() != *n {
            false;
        }
    }
    true
}
