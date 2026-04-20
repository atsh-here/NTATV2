use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha512, Digest};
use std::collections::HashSet;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use rayon::prelude::*;

use crate::base::{PublicParams, ServerSecret, Token, Witness};
use crate::utils::random_scalar;
use crate::serde_utils::{ristretto_serde, scalar_vec_serde};

pub fn derive_rate_limit_generators(epoch_id: u64, app_id: &[u8], n: usize) -> Vec<RistrettoPoint> {
    (0..n).into_par_iter().with_min_len(16).map(|i| {
        let mut hasher = Sha512::new();
        hasher.update(b"NTAT-RATE-LIMIT-V1"); hasher.update(&epoch_id.to_le_bytes());
        hasher.update(app_id); hasher.update(&(i as u64).to_le_bytes());
        RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
    }).collect()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RateLimitProof {
    pub rho: [u8; 32],
    #[serde(with = "ristretto_serde")] pub sigma: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub sigma_prime: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub tag: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub com: RistrettoPoint,
    #[serde(with = "scalar_vec_serde")] pub challenges: Vec<Scalar>,
    #[serde(with = "scalar_vec_serde")] pub z_x: Vec<Scalar>,
    #[serde(with = "scalar_vec_serde")] pub z_r: Vec<Scalar>,
    #[serde(with = "scalar_vec_serde")] pub z_s: Vec<Scalar>,
    #[serde(with = "scalar_vec_serde")] pub z_e: Vec<Scalar>,
    #[serde(with = "scalar_vec_serde")] pub z_r_com: Vec<Scalar>,
}

impl RateLimitProof {
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R, pp: &PublicParams, real_idx: usize, witness: &Witness, sigma: RistrettoPoint, sigma_prime: RistrettoPoint,
        r_com: Scalar, com: RistrettoPoint, gens: &[RistrettoPoint],
    ) -> Self {
        let n = gens.len(); let mut rho = [0u8; 32]; rng.fill_bytes(&mut rho);
        let mut f_c = Vec::with_capacity(n); let mut f_zx = Vec::with_capacity(n); let mut f_zr = Vec::with_capacity(n);
        let mut f_zs = Vec::with_capacity(n); let mut f_ze = Vec::with_capacity(n); let mut f_zr_com = Vec::with_capacity(n);
        
        for i in 0..n {
            if i != real_idx {
                f_c.push(random_scalar(rng)); f_zx.push(random_scalar(rng)); f_zr.push(random_scalar(rng));
                f_zs.push(random_scalar(rng)); f_ze.push(random_scalar(rng)); f_zr_com.push(random_scalar(rng));
            } else {
                f_c.push(Scalar::zero()); f_zx.push(Scalar::zero()); f_zr.push(Scalar::zero());
                f_zs.push(Scalar::zero()); f_ze.push(Scalar::zero()); f_zr_com.push(Scalar::zero());
            }
        }

        let tag = gens[real_idx] * witness.x; let sp_g4 = sigma_prime - pp.g4;
        let (q_ntat_commits, (q_com_commits, a_commits)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..n).into_par_iter().with_min_len(16).map(|i| {
            if i == real_idx {
                (RistrettoPoint::default(), (RistrettoPoint::default(), RistrettoPoint::default()))
            } else {
                let q_ntat_i = pp.g1 * f_zx[i] + pp.g3 * f_zr[i] + pp.g_v * f_ze[i] + sigma * f_zs[i] - sp_g4 * f_c[i];
                let q_com_i = pp.g_v * f_ze[i] + pp.g_b * f_zr_com[i] - com * f_c[i];
                let a_i = gens[i] * f_zx[i] - tag * f_c[i];
                (q_ntat_i, (q_com_i, a_i))
            }
        }).unzip();

        let v0 = random_scalar(rng); let v1 = random_scalar(rng); let v2 = random_scalar(rng);
        let v_e = random_scalar(rng); let v_r_com = random_scalar(rng);
        
        let mut q_ntat_final = q_ntat_commits; let mut q_com_final = q_com_commits; let mut a_final = a_commits;
        q_ntat_final[real_idx] = pp.g1 * v0 + pp.g3 * v1 + pp.g_v * v_e + sigma * v2;
        q_com_final[real_idx] = pp.g_v * v_e + pp.g_b * v_r_com;
        a_final[real_idx] = gens[real_idx] * v0;

        let mut hasher = Sha512::new(); hasher.update(b"NTAT:OR:BRIDGE"); hasher.update(&rho);
        for i in 0..n {
            let qn_pt: &RistrettoPoint = &q_ntat_final[i]; let qc_pt: &RistrettoPoint = &q_com_final[i]; let a_pt: &RistrettoPoint = &a_final[i];
            hasher.update(qn_pt.compress().as_bytes()); hasher.update(qc_pt.compress().as_bytes()); hasher.update(a_pt.compress().as_bytes());
        }
        let c_m = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let sum_fake: Scalar = f_c.iter().sum(); let c_real = c_m - sum_fake;

        f_c[real_idx] = c_real; f_zx[real_idx] = v0 + c_real * witness.x; f_zr[real_idx] = v1 + c_real * witness.r;
        f_zs[real_idx] = v2 - c_real * witness.s; f_ze[real_idx] = v_e + c_real * Scalar::from(witness.e); f_zr_com[real_idx] = v_r_com + c_real * r_com;

        RateLimitProof { rho, sigma, sigma_prime, tag, com, challenges: f_c, z_x: f_zx, z_r: f_zr, z_s: f_zs, z_e: f_ze, z_r_com: f_zr_com }
    }

    pub fn verify_batched(&self, pp: &PublicParams, gens: &[RistrettoPoint]) -> bool {
        let n = gens.len(); let sp_g4 = self.sigma_prime - pp.g4;
        let (q_ntat_c, (q_com_c, a_c)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..n).into_par_iter().with_min_len(16).map(|i| {
            let q_ntat_i = RistrettoPoint::vartime_multiscalar_mul(&[self.z_x[i], self.z_r[i], self.z_e[i], self.z_s[i], -self.challenges[i]], &[pp.g1, pp.g3, pp.g_v, self.sigma, sp_g4]);
            let q_com_i = RistrettoPoint::vartime_multiscalar_mul(&[self.z_e[i], self.z_r_com[i], -self.challenges[i]], &[pp.g_v, pp.g_b, self.com]);
            let a_i = RistrettoPoint::vartime_multiscalar_mul(&[self.z_x[i], -self.challenges[i]], &[gens[i], self.tag]);
            (q_ntat_i, (q_com_i, a_i))
        }).unzip();

        let mut hasher = Sha512::new(); hasher.update(b"NTAT:OR:BRIDGE"); hasher.update(&self.rho);
        for i in 0..n {
            let qn_pt: &RistrettoPoint = &q_ntat_c[i]; let qc_pt: &RistrettoPoint = &q_com_c[i]; let a_pt: &RistrettoPoint = &a_c[i];
            hasher.update(qn_pt.compress().as_bytes()); hasher.update(qc_pt.compress().as_bytes()); hasher.update(a_pt.compress().as_bytes());
        }
        let c_m = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        self.challenges.iter().sum::<Scalar>() == c_m
    }
}

pub struct RateLimitState { pub used_tags: Mutex<HashSet<[u8; 32]>>, pub generators: Vec<RistrettoPoint> }
impl RateLimitState {
    pub fn new(epoch_id: u64, app_id: Vec<u8>, n: usize) -> Self { RateLimitState { used_tags: Mutex::new(HashSet::new()), generators: derive_rate_limit_generators(epoch_id, &app_id, n) } }
}

pub fn create_rate_limited_redemption<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, token: &Token, witness: &Witness, state: &RateLimitState, slot: usize, r_com: Scalar, com: RistrettoPoint) -> (RateLimitProof, RistrettoPoint) {
    let sigma_prime = pp.g1 * witness.x + pp.g3 * witness.r + pp.g4 + pp.g_v * Scalar::from(witness.e) - token.sigma * witness.s;
    let proof = RateLimitProof::prove(rng, pp, slot, witness, token.sigma, sigma_prime, r_com, com, &state.generators);
    let tag = proof.tag;
    (proof, tag)
}

pub fn verify_rate_limited_redemption(pp: &PublicParams, sk_s: &ServerSecret, proof: &RateLimitProof, state: &RateLimitState) -> bool {
    if proof.sigma * sk_s.y != proof.sigma_prime { return false; }
    if !proof.verify_batched(pp, &state.generators) { return false; }
    let key = proof.tag.compress().to_bytes();
    let mut guard = state.used_tags.lock().unwrap();
    if guard.contains(&key) { false } else { guard.insert(key); true }
}

pub fn verify_rate_limited_proof_only(pp: &PublicParams, sk_s: &ServerSecret, proof: &RateLimitProof, state: &RateLimitState) -> bool {
    proof.sigma * sk_s.y == proof.sigma_prime && proof.verify_batched(pp, &state.generators)
}



