use crate::crypto::{CommitVec, SharePair};
use serde::{Deserialize, Serialize};

pub type Mid = (u32, u64); // (sender_id, sequence_number)

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Carry { mid: Mid, vk: CommitVec },
    Echo  { mid: Mid, vk: CommitVec },
    Ready { mid: Mid, vk: CommitVec },
    Share { mid: Mid, origin: u32, pair: SharePair },
    Collect { mid: Mid },
    Supply  { mid: Mid, origin: u32, pair: SharePair },
}

impl Message {
    pub fn mid(&self) -> Mid {
        match self {
            Message::Carry { mid, .. }
            | Message::Echo { mid, .. }
            | Message::Ready { mid, .. }
            | Message::Share { mid, .. }
            | Message::Collect { mid }
            | Message::Supply { mid, .. } => *mid,
        }
    }
}