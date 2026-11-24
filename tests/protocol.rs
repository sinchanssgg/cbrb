//! Pure state-machine tests: one per lemma, plus cleanup audit.

use crbb::crypto::*;
use crbb::message::{Message, Mid};
use crbb::protocol::{In, Node, Out};
use rand::thread_rng;
use std::collections::BTreeSet;

const N: u32 = 7;
const T: u32 = 2;
const C: u32 = 1;
const MSG_LEN: usize = 32;

fn wire(nodes: &mut [Node], outs_per_node: Vec<Vec<Out>>) {
    for (idx, outs) in outs_per_node.into_iter().enumerate() {
        for out in outs {
            match out {
                Out::ToAll(m) => {
                    for dst in 0..nodes.len() {
                        let mut rng = thread_rng();
                        let next = nodes[dst].handle(&mut rng, In::Recv { from: idx as u32, msg: m.clone() });
                        if !next.is_empty() {
                            // Feed recursively
                            let mut stack = vec![(dst, next)];
                            while let Some((d, oo)) = stack.pop() {
                                for o2 in oo {
                                    match o2 {
                                        Out::ToAll(mm) => {
                                            for dd in 0..nodes.len() {
                                                let mut rng = thread_rng();
                                                let n2 = nodes[dd].handle(&mut rng, In::Recv { from: d as u32, msg: mm.clone() });
                                                if !n2.is_empty() {
                                                    stack.push((dd, n2));
                                                }
                                            }
                                        }
                                        Out::To(p, mm) => {
                                            let mut rng = thread_rng();
                                            let n2 = nodes[p as usize].handle(&mut rng, In::Recv { from: d as u32, msg: mm });
                                            if !n2.is_empty() {
                                                stack.push((p as usize, n2));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Out::To(p, m) => {
                    let mut rng = thread_rng();
                    let next = nodes[p as usize].handle(&mut rng, In::Recv { from: idx as u32, msg: m });
                    let mut stack = vec![(p as usize, next)];
                    while let Some((d, oo)) = stack.pop() {
                        for o2 in oo {
                            match o2 {
                                Out::ToAll(mm) => {
                                    for dd in 0..nodes.len() {
                                        let mut rng = thread_rng();
                                        let n2 = nodes[dd].handle(&mut rng, In::Recv { from: d as u32, msg: mm.clone() });
                                        if !n2.is_empty() {
                                            stack.push((dd, n2));
                                        }
                                    }
                                }
                                Out::To(p, mm) => {
                                    let mut rng = thread_rng();
                                    let n2 = nodes[p as usize].handle(&mut rng, In::Recv { from: d as u32, msg: mm });
                                    if !n2.is_empty() {
                                        stack.push((p as usize, n2));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn setup() -> (Vec<Node>, Mid, Vec<u8>) {
    let mut nodes: Vec<Node> = (0..N)
        .map(|i| Node::new(i, N, T, C, MSG_LEN))
        .collect();
    let mid: Mid = (0, 1);
    let payload = vec![0x11u8; MSG_LEN];
    let mut rng = thread_rng();
    let outs = nodes[0].initiate(&mut rng, mid, &payload);
    // Wire with recursive feeding
    let mut stack: Vec<(usize, Vec<Out>)> = vec![(0, outs)];
    while let Some((src, outs)) = stack.pop() {
        for out in outs {
            match out {
                Out::ToAll(m) => {
                    for dst in 0..N as usize {
                        let mut rng = thread_rng();
                        let next = nodes[dst].handle(&mut rng, In::Recv { from: src as u32, msg: m.clone() });
                        if !next.is_empty() {
                            stack.push((dst, next));
                        }
                    }
                }
                Out::To(p, m) => {
                    let mut rng = thread_rng();
                    let next = nodes[p as usize].handle(&mut rng, In::Recv { from: src as u32, msg: m });
                    if !next.is_empty() {
                        stack.push((p as usize, next));
                    }
                }
            }
        }
    }
    // After Bracha, deliver cert
    let k = (T + C + 1) as usize;
    let readers: BTreeSet<u32> = (0..k as u32).collect();
    let mut stack: Vec<(usize, Vec<Out>)> = Vec::new();
    for i in 0..N as usize {
        let mut rng = thread_rng();
        let outs = nodes[i].handle(
            &mut rng,
            In::Certificate { mid, readers: readers.clone() },
        );
        if !outs.is_empty() {
            stack.push((i, outs));
        }
    }
    while let Some((src, outs)) = stack.pop() {
        for out in outs {
            match out {
                Out::ToAll(m) => {
                    for dst in 0..N as usize {
                        let mut rng = thread_rng();
                        let next = nodes[dst].handle(&mut rng, In::Recv { from: src as u32, msg: m.clone() });
                        if !next.is_empty() {
                            stack.push((dst, next));
                        }
                    }
                }
                Out::To(p, m) => {
                    let mut rng = thread_rng();
                    let next = nodes[p as usize].handle(&mut rng, In::Recv { from: src as u32, msg: m });
                    if !next.is_empty() {
                        stack.push((p as usize, next));
                    }
                }
            }
        }
    }
    (nodes, mid, payload)
}

#[test]
fn test_agreement() {
    let (nodes, mid, _) = setup();
    let outputs: Vec<_> = nodes
        .iter()
        .filter_map(|n| n.instances.get(&mid).and_then(|i| i.output.clone()))
        .collect();
    assert!(!outputs.is_empty(), "no reader reconstructed");
    let first = &outputs[0];
    for o in &outputs {
        assert_eq!(o, first, "readers disagree");
    }
}

#[test]
fn test_totality() {
    let (nodes, mid, _) = setup();
    // If at least one reader reconstructed, all should have.
    let any_recon = nodes
        .iter()
        .any(|n| n.instances.get(&mid).map(|i| i.recon_done).unwrap_or(false));
    if any_recon {
        for (idx, n) in nodes.iter().enumerate() {
            let readers = n.instances.get(&mid).and_then(|i| i.reader_set.as_ref());
            if let Some(rs) = readers {
                if rs.contains(&(idx as u32)) {
                    let recon = n.instances.get(&mid).map(|i| i.recon_done).unwrap_or(false);
                    assert!(recon, "reader {} did not reconstruct", idx);
                }
            }
        }
    }
}

#[test]
fn test_cleanup_audit() {
    let (nodes, mid, _) = setup();
    for n in nodes.iter() {
        if let Some(inst) = n.instances.get(&mid) {
            if inst.recon_done {
                assert!(inst.shares.is_empty(), "foreign shares remain");
                assert!(inst.pending.is_empty(), "pending remain");
                assert!(inst.own_share.is_some(), "own share was erased");
            }
        }
    }
}

#[test]
fn test_own_share_retained() {
    let (nodes, mid, _) = setup();
    for n in nodes.iter() {
        if let Some(inst) = n.instances.get(&mid) {
            if inst.recon_done {
                assert!(inst.own_share.is_some(), "own share must be retained");
            }
        }
    }
}

#[test]
fn test_invalid_share_rejected() {
    // A Byzantine (node 0) sends a malformed share to node 1.
    let mut nodes: Vec<Node> = (0..N)
        .map(|i| Node::new(i, N, T, C, MSG_LEN))
        .collect();
    let mid: Mid = (0, 1);
    let vk = {
        let mut rng = thread_rng();
        let m = 1;
        let payload = vec![0u8; 4];
        let m_vec = crbb::crypto::encode_message(&payload);
        let d = T + C;
        let p = crbb::crypto::sample_poly(&mut rng, d as usize, m_vec);
        let q = crbb::crypto::sample_blinding(&mut rng, d as usize, m);
        crbb::crypto::CommitVec::new(&p.coeffs, &q.coeffs)
    };
    let bogus = SharePair {
        sigma: vec![curve25519_dalek::scalar::Scalar::from(123u64)],
        tau: vec![curve25519_dalek::scalar::Scalar::from(456u64)],
    };
    let mut rng = thread_rng();
    let _ = nodes[1].handle(
        &mut rng,
        In::Recv {
            from: 0,
            msg: Message::Supply {
                mid,
                origin: 3,
                pair: bogus,
            },
        },
    );
    // Node 1 should not accept the bogus share
    let shares = nodes[1].instances.get(&mid).map(|i| i.shares.len()).unwrap_or(0);
    assert_eq!(shares, 0, "bogus share accepted");
}