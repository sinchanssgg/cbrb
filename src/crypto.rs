//! Cryptographic primitives for CRBB.
//!
//! - Shamir sharing of vector polynomials over the Ristretto scalar field
//!   F_q, where q is the Ristretto scalar modulus (~253 bits).
//! - Pedersen coefficient commitments in the Ristretto group.
//! - Share verification, Lagrange reconstruction, message encoding.

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
    traits::Identity,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Public generator g (Ristretto basepoint).
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Domain separator for the second Pedersen generator γ.
const GAMMA_DOMAIN: &[u8] = b"CRBB/pedersen/gamma/v1";

/// Second Pedersen generator γ with unknown log_g(γ).
pub fn gamma() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(GAMMA_DOMAIN)
}

/// Public evaluation point for process index `i` (0-based).
/// Returns `i+1` mapped to a scalar, so x_i ∈ {1, 2, ..., n}.
pub fn eval_point(i: u32) -> Scalar {
    Scalar::from((i as u64) + 1)
}

// ---------- Message encoding ----------

/// Maximum bytes per field element: 31 bytes = 248 bits, always < q.
pub const CHUNK_BYTES: usize = 31;

pub fn encode_message(m: &[u8]) -> Vec<Scalar> {
    m.chunks(CHUNK_BYTES)
        .map(|c| {
            let mut buf = [0u8; 32];
            buf[..c.len()].copy_from_slice(c);
            Scalar::from_bytes_mod_order(buf)
        })
        .collect()
}

pub fn decode_message(v: &[Scalar], total_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(total_len);
    for (i, s) in v.iter().enumerate() {
        let remaining = total_len.saturating_sub(i * CHUNK_BYTES);
        let take = remaining.min(CHUNK_BYTES);
        if take == 0 {
            break;
        }
        out.extend_from_slice(&s.to_bytes()[..take]);
    }
    out
}

pub fn num_coords(msg_len: usize) -> usize {
    (msg_len + CHUNK_BYTES - 1) / CHUNK_BYTES
}

// ---------- Polynomials over vector coefficients ----------

/// A vector polynomial: `coeffs[l]` is the coefficient of X^l,
/// and each coefficient is a vector of length m.
#[derive(Clone, Serialize, Deserialize)]
pub struct VectorPoly {
    pub coeffs: Vec<Vec<Scalar>>,
}

impl VectorPoly {
    pub fn eval(&self, x: Scalar) -> Vec<Scalar> {
        let m = self.coeffs[0].len();
        let mut acc = vec![Scalar::ZERO; m];
        let mut xp = Scalar::ONE;
        for c in &self.coeffs {
            for u in 0..m {
                acc[u] += c[u] * xp;
            }
            xp *= x;
        }
        acc
    }
}

// ---------- Pedersen commitment vector ----------

#[derive(Clone, Serialize, Deserialize)]
pub struct CommitVec {
    /// `vk[l][u] = g^{a_l[u]} γ^{b_l[u]}`; dimensions (d+1) × m.
    pub vk: Vec<Vec<RistrettoPoint>>,
}

impl CommitVec {
    pub fn new(a: &[Vec<Scalar>], b: &[Vec<Scalar>]) -> Self {
        let gamma = gamma();
        let vk = a
            .iter()
            .zip(b.iter())
            .map(|(al, bl)| {
                al.iter()
                    .zip(bl.iter())
                    .map(|(ai, bi)| G * ai + gamma * bi)
                    .collect()
            })
            .collect();
        Self { vk }
    }

    pub fn d(&self) -> usize {
        self.vk.len() - 1
    }

    pub fn m(&self) -> usize {
        self.vk[0].len()
    }

    /// Verify g^σ_u · γ^τ_u = ∏_{l=0}^d vk[l][u]^{x^l} for all u.
    pub fn verify(&self, x: Scalar, sigma: &[Scalar], tau: &[Scalar]) -> bool {
        if sigma.len() != self.m() || tau.len() != self.m() {
            return false;
        }
        let gamma = gamma();
        let d = self.d();
        let m = self.m();
        // x^0, x^1, ..., x^d
        let mut xp = Vec::with_capacity(d + 1);
        let mut p = Scalar::ONE;
        for _ in 0..=d {
            xp.push(p);
            p *= x;
        }
        for u in 0..m {
            let lhs = G * sigma[u] + gamma * tau[u];
            let mut rhs = RistrettoPoint::identity();
            for l in 0..=d {
                rhs += self.vk[l][u] * xp[l];
            }
            if lhs != rhs {
                return false;
            }
        }
        true
    }
}

// ---------- Share pair ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharePair {
    pub sigma: Vec<Scalar>,
    pub tau: Vec<Scalar>,
}

// ---------- Lagrange interpolation at zero ----------

/// Interpolate σ_u(0) for each coordinate u, given k shares.
/// `points[j] = (x_j, share_j)`. Returns a vector of length m.
pub fn lagrange_at_zero(points: &[(Scalar, SharePair)]) -> Vec<Scalar> {
    let m = points[0].1.sigma.len();
    let mut out = vec![Scalar::ZERO; m];
    for (j, (xj, share_j)) in points.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (i, (xi, _)) in points.iter().enumerate() {
            if i != j {
                num *= *xi;
                den *= *xi - *xj;
            }
        }
        let coef = num * den.invert();
        for u in 0..m {
            out[u] += share_j.sigma[u] * coef;
        }
    }
    out
}

// ---------- Polynomial generation ----------

/// Sample a degree-d vector polynomial with constant term `m_vec`
/// and random nonconstant coefficients.
pub fn sample_poly<R: CryptoRngCore>(
    rng: &mut R,
    d: usize,
    m_vec: Vec<Scalar>,
) -> VectorPoly {
    let m = m_vec.len();
    let mut coeffs = Vec::with_capacity(d + 1);
    coeffs.push(m_vec);
    for _ in 1..=d {
        let mut c = Vec::with_capacity(m);
        for _ in 0..m {
            c.push(Scalar::random(rng));
        }
        coeffs.push(c);
    }
    VectorPoly { coeffs }
}

/// Sample a degree-d vector polynomial of blinding coefficients,
/// with random constant term.
pub fn sample_blinding<R: CryptoRngCore>(rng: &mut R, d: usize, m: usize) -> VectorPoly {
    let mut coeffs = Vec::with_capacity(d + 1);
    for _ in 0..=d {
        let mut c = Vec::with_capacity(m);
        for _ in 0..m {
            c.push(Scalar::random(rng));
        }
        coeffs.push(c);
    }
    VectorPoly { coeffs }
}


// ================= CRBB-H additions: digest and batched verification =================

use sha2::{Digest, Sha256};

/// Domain-separated digest of a commitment vector bound to `mid`.
pub fn digest_vk(mid: (u32, u64), vk: &CommitVec) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CRBB/vk-digest/v1");
    hasher.update(mid.0.to_le_bytes());
    hasher.update(mid.1.to_le_bytes());
    for row in &vk.vk {
        for p in row {
            hasher.update(p.compress().as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Wire length of a commitment vector, in bytes, when transmitted raw.
pub fn vk_wire_len(d: usize, m: usize) -> usize {
    (d + 1) * m * 32
}

/// Combine commitments with a random vector `r`:
/// `combined[l] = sum_u vk[l][u] * r[u]`. Cost is `(d+1)*m` group ops —
/// approximately one exact verification.
pub fn combine_commitments(vk: &CommitVec, r: &[Scalar]) -> Vec<RistrettoPoint> {
    let d = vk.d();
    let m = vk.m();
    assert_eq!(r.len(), m, "batch vector length mismatch");
    let mut combined = Vec::with_capacity(d + 1);
    for l in 0..=d {
        let mut acc = RistrettoPoint::identity();
        for u in 0..m {
            acc += vk.vk[l][u] * r[u];
        }
        combined.push(acc);
    }
    combined
}

/// Inner product of two field vectors.
pub fn dot(r: &[Scalar], v: &[Scalar]) -> Scalar {
    let mut acc = Scalar::ZERO;
    for (a, b) in r.iter().zip(v.iter()) {
        acc += a * b;
    }
    acc
}

/// Batched share verification: `g^<r,σ> · γ^<r,τ> = ∏_l combined[l]^{x^l}`.
/// Accepts the same pairs as `CommitVec::verify` except with probability
/// `≤ 1/q` per check for a fixed `r`.
pub fn batch_verify(
    x: Scalar,
    sigma: &[Scalar],
    tau: &[Scalar],
    r: &[Scalar],
    combined: &[RistrettoPoint],
) -> bool {
    if sigma.len() != r.len() || tau.len() != r.len() {
        return false;
    }
    let s = dot(r, sigma);
    let t = dot(r, tau);
    let lhs = G * s + gamma() * t;
    let mut xp = Scalar::ONE;
    let mut rhs = RistrettoPoint::identity();
    for c in combined {
        rhs += *c * xp;
        xp *= x;
    }
    lhs == rhs
}