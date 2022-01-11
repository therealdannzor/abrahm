use super::{
    engine::{State, M},
    view::ViewChangeMessage,
};
use std::collections::HashMap;
use swiss_knife::{hashed, helper::generate_hash_from_input};

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

// Filters all viewchange messages of the same view.
pub fn filter_viewchange(needle: View, haystack: Vec<ViewChangeMessage>) -> Vec<ViewChangeMessage> {
    let mut result: Vec<ViewChangeMessage> = Vec::new();
    for vc in haystack.iter().clone() {
        if vc.next_view() == needle {
            result.push(vc.clone());
        }
    }
    result
}

// Filters all messages in the same consensus phase. Does not modify input.
pub fn filter_phase(needle: State, haystack: &Vec<M>) -> Vec<M> {
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

pub fn count_viewchange_votes(haystack: Vec<ViewChangeMessage>) -> (String, usize) {
    let mut most_popular = String::from("");
    let mut most_amount = 0;
    let mut map = HashMap::<String, usize>::new();
    for vc in haystack.iter() {
        let big_p = vc.big_p();
        let first_dat = big_p[0].clone().message();
        let c = map.entry(first_dat.d.clone()).or_insert(0);
        *c += 1;
        if *c > most_amount {
            most_popular = first_dat.d;
            most_amount = *c;
        }
    }
    (most_popular, most_amount)
}

// Returns true if `haystack` contains at least `count` messages `m`, else false
pub fn correct_message_set(m: Option<M>, haystack: Vec<M>, count: usize) -> bool {
    let mut counter = 0;
    if m.is_none() {
        false;
    }

    for n in haystack.iter().clone() {
        // only verify that the digests are equal (i.e. same Request)
        if m.clone().unwrap().d != *n.d {
            false;
        } else {
            counter += 1;
        }
    }
    counter >= count
}

pub fn gt_two_thirds(set_size: usize) -> usize {
    2 * ((set_size as f64 - 1f64) / 3 as f64) as usize + 1
}
