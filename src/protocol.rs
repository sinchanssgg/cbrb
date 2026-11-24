//! Per-broadcast CRBB state machine.
//! Pure (no I/O): `Node::handle` takes inputs and returns outgoing messages.

use crate::crypto::*;
use crate::message::{Message, Mid};
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};

use crate::byzantine::{ByzantineConfig, ByzantineMode};
use crate::crypto::{
    batch_verify, combine_commitments, digest_vk, vk_wire_len, CommitVec, SharePair,
};
use crate::variant::Variant;
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub struct Instance {
    // Bracha state
    pub echo_sent: Option<CommitVec>,
    pub ready_sent: Option<CommitVec>,
    pub echo_recv: BTreeMap<u32, CommitVec>, // sender -> VK
    pub ready_recv: BTreeMap<u32, CommitVec>,
    pub vk: Option<CommitVec>,

    // Share state
    pub own_raw: Option<SharePair>,
    pub own_share: Option<SharePair>,
    pub own_processed: bool,
    pub own_dispatched: bool,
    pub shares: BTreeMap<u32, SharePair>,
    pub pending: BTreeMap<(u32, u32), SharePair>, // (origin, sender) -> pair
    pub requesters: BTreeSet<u32>,
    pub responded: BTreeSet<u32>,
    pub collect_sent: bool,

    // Certificate (reader set)
    pub reader_set: Option<BTreeSet<u32>>,

    // Reconstruction
    pub recon_done: bool,
    pub output: Option<Vec<u8>>,

        // CRBB-H: digest dissemination
    pub local_vk: Option<CommitVec>,             // V from CARRY (or any ECHO)
    pub vk_digest: Option<[u8; 32]>,             // adopted digest
    pub echo_digest_sent: Option<[u8; 32]>,
    pub ready_digest_sent: Option<[u8; 32]>,
    pub echo_digest_recv: BTreeMap<u32, [u8; 32]>,
    pub ready_digest_recv: BTreeMap<u32, [u8; 32]>,
    pub req_sent_for: Option<[u8; 32]>,
    pub req_targets: BTreeSet<u32>,
    pub replied_to: BTreeSet<u32>,
    // CRBB-H: batch verification
    pub batch_r: Option<Vec<Scalar>>,
    pub batch_combined: Option<Vec<curve25519_dalek::ristretto::RistrettoPoint>>,
    // Byzantine S6: count of forged supplies sent
    pub flood_sent: u32,
}

pub struct Node {
    pub id: u32,
    pub n: u32,
    pub t: u32,
    pub c: u32,
    pub message_len: usize, // bytes
    pub instances: BTreeMap<Mid, Instance>,
    pub variant: Variant,
    pub byz: ByzantineConfig,
}

pub enum Out {
    ToAll(Message),
    To(u32, Message),
}

pub enum In {
    /// Message received from peer `from`.
    Recv { from: u32, msg: Message },
    /// Certificate adopted (reader set).
    Certificate { mid: Mid, readers: BTreeSet<u32> },
    /// Sender invocation: initiate broadcast of `payload`.
    Initiate { mid: Mid, payload: Vec<u8> },
    /// (Internal) time to check triggers. In practice called after each Recv.
    Tick,
}

impl Node {
    pub fn new(id: u32, n: u32, t: u32, c: u32, message_len: usize) -> Self {
        Self {
            id, n, t, c, message_len,
            instances: BTreeMap::new(),
            variant: Variant::Crbb,
            byz: ByzantineConfig::default(),
        }
    }

    pub fn with_variant(mut self, v: Variant) -> Self {
        self.variant = v;
        self
    }

    pub fn with_byzantine(mut self, b: ByzantineConfig) -> Self {
        self.byz = b;
        self
    }

    pub fn d(&self) -> usize {
        (self.t + self.c) as usize
    }

    pub fn k(&self) -> usize {
        self.d() + 1
    }

    fn inst(&mut self, mid: Mid) -> &mut Instance {
        self.instances.entry(mid).or_default()
    }

    /// Initiate a broadcast. Called by the sender only.
    pub fn initiate<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        mid: Mid,
        payload: &[u8],
    ) -> Vec<Out> {
        assert_eq!(mid.0, self.id, "only the sender can initiate");
        let m = num_coords(payload.len());
        let d = self.d();
        let m_vec = encode_message(payload);
        let p_poly = sample_poly(rng, d, m_vec);
        let q_poly = sample_blinding(rng, d, m);
        let vk = CommitVec::new(&p_poly.coeffs, &q_poly.coeffs);

        let mut out = Vec::new();
        // 1) SHARE to every holder in H = P \ {sender}
        for j in 0..self.n {
            if j == self.id {
                continue;
            }
            let xj = eval_point(j);
            let pair = SharePair {
                sigma: p_poly.eval(xj),
                tau: q_poly.eval(xj),
            };
            out.push(Out::To(j, Message::Share { mid, origin: j, pair }));
        }
        // 2) CARRY to all (including self via broadcast)
        out.push(Out::ToAll(Message::Carry { mid, vk }));

        // Sender's local state: we pretend the sender "receives" the CARRY
        // locally, so its Bracha handler will run. But we don't need to
        // store P, Q — they are erased once the sender's local Bracha
        // delivers VK. For simplicity, we let the state machine handle
        // the local CARRY via handle() below.
        out
    }

    pub fn handle<R: CryptoRngCore>(&mut self, rng: &mut R, input: In) -> Vec<Out> {
        let mut out = Vec::new();
        match input {
            In::Initiate { .. } => unreachable!("use initiate()"),
            In::Recv { from, msg } => {
                let mid = msg.mid();
                match msg {
                    Message::Carry { mid, vk } => {
                        self.on_carry(&mut out, mid, vk);
                    }
                    Message::Echo { mid, vk } => {
                        self.on_echo(&mut out, from, mid, vk);
                    }
                    Message::Ready { mid, vk } => {
                        self.on_ready(&mut out, from, mid, vk);
                    }
                    Message::Share { mid, origin, pair } => {
                        self.on_share(&mut out, from, mid, origin, pair);
                    }
                    Message::Collect { mid } => {
                        self.on_collect(&mut out, from, mid);
                    }
                    Message::Supply { mid, origin, pair } => {
                        self.on_supply(&mut out, from, mid, origin, pair);
                    }
                }
                let _ = mid;
            }
            In::Certificate { mid, readers } => {
                self.on_certificate(&mut out, mid, readers);
            }
            In::Tick => {
                // Triggers are checked after each message anyway.
            }
        }
        // After any input, run the "whenever" triggers.
        self.run_triggers(rng, &mut out);
        out
    }

    // --- Bracha handlers ---

    fn on_carry(&mut self, out: &mut Vec<Out>, mid: Mid, vk: CommitVec) {
        let t = self.t;
        let n = self.n;
        let inst = self.inst(mid);
        if inst.echo_sent.is_some() {
            return;
        }
        // Defensive: don't ECHO a VK conflicting with an adopted one.
        if let Some(current) = &inst.vk {
            if !same_vk(current, &vk) {
                return;
            }
        }
        inst.echo_sent = Some(vk.clone());
        out.push(Out::ToAll(Message::Echo { mid, vk }));
        let _ = (t, n);
    }

    fn on_echo(&mut self, out: &mut Vec<Out>, from: u32, mid: Mid, vk: CommitVec) {
        let n = self.n;
        let t = self.t;
        let inst = self.inst(mid);
        if inst.echo_recv.contains_key(&from) {
            return;
        }
        inst.echo_recv.insert(from, vk.clone());

        // Count matching ECHOs for this VK
        let count = inst.echo_recv.values().filter(|v| same_vk(v, &vk)).count();

        // n-t matching ECHOs → send READY (if not sent)
        if count >= (n - t) as usize && inst.ready_sent.is_none() {
            // Adopt if not yet adopted
            if inst.vk.is_none() {
                inst.vk = Some(vk.clone());
            }
            inst.ready_sent = Some(vk.clone());
            out.push(Out::ToAll(Message::Ready { mid, vk: vk.clone() }));
        }
        let _ = t;
    }

    fn on_ready(&mut self, out: &mut Vec<Out>, from: u32, mid: Mid, vk: CommitVec) {
        let n = self.n;
        let t = self.t;
        let inst = self.inst(mid);
        if inst.ready_recv.contains_key(&from) {
            return;
        }
        inst.ready_recv.insert(from, vk.clone());

        let count = inst.ready_recv.values().filter(|v| same_vk(v, &vk)).count();

        // t+1 matching READYs → amplification: send READY if not sent
        if count >= (t + 1) as usize && inst.ready_sent.is_none() {
            if inst.vk.is_none() {
                inst.vk = Some(vk.clone());
            }
            inst.ready_sent = Some(vk.clone());
            out.push(Out::ToAll(Message::Ready { mid, vk: vk.clone() }));
        }

        // n-t matching READYs → adopt VK
        if count >= (n - t) as usize && inst.vk.is_none() {
            inst.vk = Some(vk);
        }
    }

    // --- Share handlers ---

    fn on_share(&mut self, _out: &mut Vec<Out>, from: u32, mid: Mid, origin: u32, pair: SharePair) {
        // Only accept SHARE from the sender, for our own origin.
        if from != mid.0 || origin != self.id {
            return;
        }
        let inst = self.inst(mid);
        if inst.own_raw.is_none() {
            inst.own_raw = Some(pair);
        }
    }

    fn on_collect(&mut self, _out: &mut Vec<Out>, from: u32, mid: Mid) {
        // Only readers may collect.
        let inst = self.inst(mid);
        if let Some(rs) = &inst.reader_set {
            if !rs.contains(&from) {
                return;
            }
        } else {
            return; // no certificate yet; ignore
        }
        inst.requesters.insert(from);
    }

    fn on_supply(&mut self, out: &mut Vec<Out>, from: u32, mid: Mid, origin: u32, pair: SharePair) {
        // Admission: (from ∈ R_mid) ∨ (from == origin)
        let inst = self.inst(mid);
        let reader_set = match &inst.reader_set {
            Some(rs) => rs.clone(),
            None => {
                // No certificate yet: buffer (per paper) if not duplicate.
                if inst.pending.get(&(origin, from)).is_none() {
                    inst.pending.insert((origin, from), pair);
                }
                return;
            }
        };
        let from_is_reader = reader_set.contains(&from);
        if !(from_is_reader || from == origin) {
            return;
        }
        if !reader_set.contains(&self.id) {
            return; // not a reader; discard
        }
        if inst.recon_done {
            return;
        }
        let vk = match &inst.vk {
            Some(v) => v.clone(),
            None => {
                if inst.pending.get(&(origin, from)).is_none() {
                    inst.pending.insert((origin, from), pair);
                }
                return;
            }
        };
        self.accept_share(out, mid, origin, pair, from, &vk);
    }

    // --- Certificate handler ---

    fn on_certificate(&mut self, _out: &mut Vec<Out>, mid: Mid, readers: BTreeSet<u32>) {
        let inst = self.inst(mid);
        if inst.reader_set.is_some() {
            return; // certificate is issued at most once
        }
        inst.reader_set = Some(readers);
    }

    // --- Core AcceptShare ---

    #[allow(clippy::too_many_arguments)]
    fn accept_share(
        &mut self,
        out: &mut Vec<Out>,
        mid: Mid,
        origin: u32,
        pair: SharePair,
        from: u32,
        vk: &CommitVec,
    ) {
        let me = self.id;
        let inst = self.inst(mid);
        if inst.recon_done {
            return;
        }
        if origin >= self.n {
            return;
        }
        if inst.shares.contains_key(&origin) {
            return;
        }
        let x = eval_point(origin);
        if !vk.verify(x, &pair.sigma, &pair.tau) {
            return;
        }
        inst.shares.insert(origin, pair.clone());
        if origin == me && inst.own_share.is_none() {
            inst.own_share = Some(pair.clone());
        }

        // Relay to R_mid \ {self, from}
        if let Some(rs) = &inst.reader_set {
            let targets: Vec<u32> = rs
                .iter()
                .copied()
                .filter(|&j| j != me && j != from)
                .collect();
            for j in targets {
                out.push(Out::To(
                    j,
                    Message::Supply { mid, origin, pair: pair.clone() },
                ));
            }
        }
    }

    // --- Periodic "whenever" triggers ---

    fn run_triggers<R: CryptoRngCore>(&mut self, _rng: &mut R, out: &mut Vec<Out>) {
        let me = self.id;
        let mids: Vec<Mid> = self.instances.keys().copied().collect();
        for mid in mids {
            // Clone the pieces we need; avoids borrow issues.
            let (vk, reader_set, own_share, recon_done, pending, requesters,
                 responded, own_processed, own_dispatched, collect_sent,
                 own_raw, shares_count) = {
                let i = &self.instances[&mid];
                (
                    i.vk.clone(),
                    i.reader_set.clone(),
                    i.own_share.clone(),
                    i.recon_done,
                    i.pending.clone(),
                    i.requesters.clone(),
                    i.responded.clone(),
                    i.own_processed,
                    i.own_dispatched,
                    i.collect_sent,
                    i.own_raw.clone(),
                    i.shares.len(),
                )
            };

            // 1) Own share verification
            if !own_processed {
                if let (Some(raw), Some(v)) = (own_raw.clone(), vk.clone()) {
                    let x = eval_point(me);
                    let valid = v.eval_verify(&raw, x);
                    let inst = self.inst(mid);
                    inst.own_processed = true;
                    if valid {
                        if inst.own_share.is_none() {
                            inst.own_share = Some(raw);
                        }
                    }
                    inst.own_raw = None;
                }
            }

            // 2) Own-share dispatch (self-accept for readers; push to
            //    readers for non-readers)
            if !own_dispatched {
                if let (Some(own), Some(rs)) = (own_share.clone(), reader_set.clone()) {
                    let inst = self.inst(mid);
                    inst.own_dispatched = true;
                    if rs.contains(&me) {
                        if !recon_done {
                            let v = vk.clone().unwrap();
                            self.accept_share(out, mid, me, own, me, &v);
                        }
                    } else {
                        for r in &rs {
                            out.push(Out::To(
                                *r,
                                Message::Supply { mid, origin: me, pair: own.clone() },
                            ));
                        }
                    }
                }
            }

            // 3) Pending flush (once VK and certificate are available)
            if let (Some(v), Some(rs)) = (vk.clone(), reader_set.clone()) {
                if rs.contains(&me) && !pending.is_empty() {
                    let pending_snapshot = pending.clone();
                    for ((origin, from), pair) in pending_snapshot {
                        self.accept_share(out, mid, origin, pair, from, &v);
                    }
                    self.inst(mid).pending.clear();
                }
            }

            // 4) COLLECT (readers only, once VK adopted)
            if !collect_sent {
                if let (Some(_), Some(rs)) = (vk.clone(), reader_set.clone()) {
                    if rs.contains(&me) {
                        let inst = self.inst(mid);
                        inst.collect_sent = true;
                        out.push(Out::ToAll(Message::Collect { mid }));
                    }
                }
            }

            // 5) Respond to COLLECT requests
            if let (Some(_own), Some(_rs)) = (own_share.clone(), reader_set.clone()) {
                let to_respond: Vec<u32> =
                    requesters.difference(&responded).copied().collect();
                if !to_respond.is_empty() {
                    let own = own_share.clone().unwrap();
                    let inst = self.inst(mid);
                    for r in &to_respond {
                        inst.responded.insert(*r);
                    }
                    for r in to_respond {
                        out.push(Out::To(
                            r,
                            Message::Supply { mid, origin: me, pair: own.clone() },
                        ));
                    }
                }
            }

            // 6) Reconstruction
            if !recon_done && shares_count >= self.k() {
                if let Some(rs) = &reader_set {
                    if rs.contains(&me) {
                        self.try_reconstruct(mid, out);
                    }
                }
            }
        }
    }

    fn try_reconstruct(&mut self, mid: Mid, _out: &mut Vec<Out>) {
        let me = self.id;
        let k = self.k();
        let inst = self.inst(mid);
        let mut origins: Vec<u32> = inst.shares.keys().copied().collect();
        origins.sort_unstable();
        if origins.len() < k {
            return;
        }
        let chosen: Vec<u32> = origins.into_iter().take(k).collect();
        let points: Vec<(Scalar, SharePair)> = chosen
            .iter()
            .map(|&o| (eval_point(o), inst.shares[&o].clone()))
            .collect();
        let m_vec = lagrange_at_zero(&points);
        let payload = decode_message(&m_vec, self.message_len);
        inst.recon_done = true;
        inst.output = Some(payload);
        inst.shares.clear();
        inst.pending.clear();
        let _ = me;
    }
}

// ---------- Helpers ----------

fn same_vk(a: &CommitVec, b: &CommitVec) -> bool {
    if a.vk.len() != b.vk.len() { return false; }
    for (ra, rb) in a.vk.iter().zip(b.vk.iter()) {
        if ra.len() != rb.len() { return false; }
        for (pa, pb) in ra.iter().zip(rb.iter()) {
            if pa.compress() != pb.compress() { return false; }
        }
    }
    true
}

impl CommitVec {
    /// Convenience: verify against an already-constructed pair.
    pub fn eval_verify(&self, pair: &SharePair, x: Scalar) -> bool {
        self.verify(x, &pair.sigma, &pair.tau)
    }
}