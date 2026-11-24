use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::scalar::Scalar;
use crbb::crypto::*;
use rand::thread_rng;

fn bench_commit(c: &mut Criterion) {
    let mut g = c.benchmark_group("commit");
    for d in [8usize, 16, 24, 32] {
        let m = 32; // coordinates
        let mut rng = thread_rng();
        let a: Vec<Vec<Scalar>> = (0..=d)
            .map(|_| (0..m).map(|_| Scalar::random(&mut rng)).collect())
            .collect();
        let b: Vec<Vec<Scalar>> = (0..=d)
            .map(|_| (0..m).map(|_| Scalar::random(&mut rng)).collect())
            .collect();
        g.bench_with_input(BenchmarkId::from_parameter(d), &d, |bencher, _| {
            bencher.iter(|| CommitVec::new(black_box(&a), black_box(&b)));
        });
    }
    g.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify");
    for d in [8usize, 16, 24, 32] {
        let m = 32;
        let mut rng = thread_rng();
        let a: Vec<Vec<Scalar>> = (0..=d)
            .map(|_| (0..m).map(|_| Scalar::random(&mut rng)).collect())
            .collect();
        let b: Vec<Vec<Scalar>> = (0..=d)
            .map(|_| (0..m).map(|_| Scalar::random(&mut rng)).collect())
            .collect();
        let vk = CommitVec::new(&a, &b);
        let p_poly = VectorPoly { coeffs: a };
        let q_poly = VectorPoly { coeffs: b };
        let x = eval_point(3);
        let sigma = p_poly.eval(x);
        let tau = q_poly.eval(x);
        g.bench_with_input(BenchmarkId::from_parameter(d), &d, |bencher, _| {
            bencher.iter(|| vk.verify(black_box(x), black_box(&sigma), black_box(&tau)));
        });
    }
    g.finish();
}

fn bench_lagrange(c: &mut Criterion) {
    let mut g = c.benchmark_group("lagrange");
    for d in [8usize, 16, 24, 32] {
        let m = 32;
        let mut rng = thread_rng();
        let points: Vec<(Scalar, SharePair)> = (0..=d)
            .map(|j| {
                let sigma = (0..m).map(|_| Scalar::random(&mut rng)).collect();
                let tau = (0..m).map(|_| Scalar::random(&mut rng)).collect();
                (eval_point(j as u32), SharePair { sigma, tau })
            })
            .collect();
        g.bench_with_input(BenchmarkId::from_parameter(d), &d, |bencher, _| {
            bencher.iter(|| lagrange_at_zero(black_box(&points)));
        });
    }
    g.finish();
}

fn bench_encode(c: &mut Criterion) {
    let payload = vec![0x42u8; 1024];
    c.bench_function("encode_1024", |b| {
        b.iter(|| encode_message(black_box(&payload)));
    });
    let v = encode_message(&payload);
    c.bench_function("decode_1024", |b| {
        b.iter(|| decode_message(black_box(&v), 1024));
    });
}

criterion_group!(benches, bench_commit, bench_verify, bench_lagrange, bench_encode);
criterion_main!(benches);