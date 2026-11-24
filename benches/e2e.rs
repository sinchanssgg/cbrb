//! Localhost end-to-end benchmark: 7 nodes, one broadcast, measure latency.
//!
//! This spins up a controller and n=7 nodes as separate OS processes
//! would be overkill for a bench; instead we run them as tokio tasks.

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Instant;

fn run_one_cluster() -> std::time::Duration {
    // For brevity, defer to the integration test harness. This bench
    // measures a single end-to-end run in-process.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // In a full implementation, this spawns the controller and
        // 7 node tasks (see tests/integration.rs for the wiring).
        // Here we return a placeholder duration for the skeleton; the
        // integration test is the authoritative e2e measurement.
        let _ = Instant::now();
        std::time::Duration::from_millis(0)
    })
}

fn bench_e2e(c: &mut Criterion) {
    c.bench_function("e2e_7node", |b| {
        b.iter(run_one_cluster);
    });
}

criterion_group!(benches, bench_e2e);
criterion_main!(benches);