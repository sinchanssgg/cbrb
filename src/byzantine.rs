//! Byzantine strategy for fault-injection experiments S1–S6.
//!
//! A process configured with `mode != Honest` deviates from the protocol
//! according to the mode. The short-circuit in `Node::handle` consults
//! the mode before dispatching the input; `Node::initiate` consults it
//! before sending the sender's messages.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByzantineMode {
    /// Correct behavior.
    Honest,
    /// S1: withhold own share; never respond to COLLECT.
    WithholdShares,
    /// S2: on COLLECT, send a forged share (random sigma/tau) in addition
    /// to the real one, testing that readers reject invalid pairs.
    ForgeSupply,
    /// S3: sender sends two different VKs to two partitions of the
    /// population, testing that Bracha agreement still holds.
    EquivocateVK,
    /// S4: sender distributes valid shares to only `k - 1` holders,
    /// leaving one short; a designated helper (see `designated_helper`)
    /// hand-delivers the missing share to one target reader, testing that
    /// the relay restores totality.
    WithholdBeyondK,
    /// S6: reader floods a target's pending buffer with SUPPLY messages
    /// before the target adopts VK, testing the pending-buffer bound.
    FloodPending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ByzantineConfig {
    pub mode: ByzantineMode,
    /// For S3: process ids that will receive the *second* VK. All other
    /// non-Byzantine processes receive the first VK.
    #[serde(default)]
    pub equivocate_partition: Vec<u32>,
    /// For S4: process ids skipped by the sender when distributing shares.
    /// If empty, the sender skips the last `c + 1` correct processes.
    #[serde(default)]
    pub excluded_holders: Vec<u32>,
    /// For S4: process id of the Byzantine holder that acts as helper.
    #[serde(default)]
    pub designated_helper: Option<u32>,
    /// For S4: target reader that the helper hand-delivers to.
    #[serde(default)]
    pub helper_target_reader: Option<u32>,
    /// For S6: target reader whose pending buffer is flooded.
    #[serde(default)]
    pub flood_target: Option<u32>,
    /// For S6: number of forged SUPPLY messages to send.
    #[serde(default = "default_flood_count")]
    pub flood_count: u32,
}

fn default_flood_count() -> u32 {
    3000
}

impl Default for ByzantineConfig {
    fn default() -> Self {
        Self {
            mode: ByzantineMode::Honest,
            equivocate_partition: vec![],
            excluded_holders: vec![],
            designated_helper: None,
            helper_target_reader: None,
            flood_target: None,
            flood_count: default_flood_count(),
        }
    }
}

impl ByzantineConfig {
    pub fn is_byzantine(&self) -> bool {
        self.mode != ByzantineMode::Honest
    }
}