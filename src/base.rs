use bulletproofs::PedersenGens;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha512, Digest};
use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, RwLock},
    time::SystemTime,
};
use rand::Rng;
use crate::utils::random_scalar;
use crate::serde_utils::ristretto_serde;
use serde::{Serialize, Deserialize};

#[derive(Clone)]
pub struct PublicParams {
    pub g1: RistrettoPoint, pub g2: RistrettoPoint, pub g3: RistrettoPoint, pub g4: RistrettoPoint,
    pub g_v: RistrettoPoint, pub g_b: RistrettoPoint, 
}

impl PublicParams {
    pub fn setup() -> Self {
        fn gen_from_seed(seed: &[u8]) -> RistrettoPoint {
            let hash = Sha512::new().chain_update(seed).finalize();
            RistrettoPoint::from_uniform_bytes(&hash.into())
        }
        let pc_gens = PedersenGens::default();
        PublicParams {
            g1: gen_from_seed(b"NTAT:G1"), g2: gen_from_seed(b"NTAT:G2"), g3: gen_from_seed(b"NTAT:G3"), g4: gen_from_seed(b"NTAT:G4"),
            g_v: pc_gens.B, g_b: pc_gens.B_blinding,
        }
    }
}

#[derive(Clone)] pub struct ClientSecret { pub x: Scalar }
impl ClientSecret {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self { ClientSecret { x: random_scalar(rng) } }
    pub fn public(&self, pp: &PublicParams) -> ClientPublic { ClientPublic { x: pp.g1 * self.x } }
}
#[derive(Clone)] pub struct ClientPublic { pub x: RistrettoPoint }
#[derive(Clone)] pub struct ServerSecret { pub y: Scalar }
impl ServerSecret {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self { ServerSecret { y: random_scalar(rng) } }
    pub fn public(&self, pp: &PublicParams) -> ServerPublic { ServerPublic { y: pp.g2 * self.y } }
}
#[derive(Clone)] pub struct ServerPublic { pub y: RistrettoPoint }

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientProof { pub ch: Scalar, pub resp1: Scalar, pub resp2: Scalar, pub resp3: Scalar }

impl ClientProof {
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, pk_s: &ServerPublic, x: RistrettoPoint, x_val: Scalar, r: Scalar, delta: Scalar, t: RistrettoPoint) -> Self {
        let delta_prime = -delta.invert();
        let a = random_scalar(rng); let b = random_scalar(rng); let c = random_scalar(rng);
        let comm1 = pp.g1 * a; let comm2 = pp.g1 * a + pp.g3 * b + t * c;
        let ch = Self::hash_challenge(pp, pk_s, &x, &t, &comm1, &comm2);
        let resp1 = a - ch * x_val; let resp2 = b - ch * r; let resp3 = c - ch * delta_prime;
        ClientProof { ch, resp1, resp2, resp3 }
    }
    pub fn verify(&self, pp: &PublicParams, pk_s: &ServerPublic, x: &RistrettoPoint, t: &RistrettoPoint, e: u64) -> bool {
        let g4_prime = pp.g4 + pp.g_v * Scalar::from(e);
        let comm1 = pp.g1 * self.resp1 + *x * self.ch;
        let comm2 = pp.g1 * self.resp1 + pp.g3 * self.resp2 + *t * self.resp3 - g4_prime * self.ch;
        let ch_prime = Self::hash_challenge(pp, pk_s, x, t, &comm1, &comm2);
        ch_prime == self.ch
    }
    fn hash_challenge(pp: &PublicParams, pk_s: &ServerPublic, x: &RistrettoPoint, t: &RistrettoPoint, comm1: &RistrettoPoint, comm2: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha512::new(); hasher.update(b"NTAT:H1:");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(pp.g1.compress().as_bytes()); bytes.extend_from_slice(pp.g3.compress().as_bytes());
        bytes.extend_from_slice(pp.g4.compress().as_bytes()); bytes.extend_from_slice(pp.g_v.compress().as_bytes());
        bytes.extend_from_slice(pk_s.y.compress().as_bytes()); bytes.extend_from_slice(x.compress().as_bytes());
        bytes.extend_from_slice(t.compress().as_bytes()); bytes.extend_from_slice(comm1.compress().as_bytes());
        bytes.extend_from_slice(comm2.compress().as_bytes()); hasher.update(&bytes);
        Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerProof { pub ch: Scalar, pub resp: Scalar }
impl ServerProof {
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, y: Scalar, y_point: RistrettoPoint, s: Scalar, t: RistrettoPoint, s_val: RistrettoPoint) -> Self {
        let a = random_scalar(rng); let comm1 = pp.g2 * a; let comm2 = s_val * a;
        let ch = Self::hash_challenge(pp, &y_point, &s_val, &(t - s * s_val), &comm1, &comm2);
        let resp = a - ch * y;
        ServerProof { ch, resp }
    }
    pub fn verify(&self, pp: &PublicParams, y_point: &RistrettoPoint, s: Scalar, t: &RistrettoPoint, s_val: &RistrettoPoint) -> bool {
        let lhs = t - s * s_val;
        let comm1 = pp.g2 * self.resp + *y_point * self.ch; let comm2 = *s_val * self.resp + lhs * self.ch;
        let ch_prime = Self::hash_challenge(pp, y_point, s_val, &lhs, &comm1, &comm2);
        ch_prime == self.ch
    }
    fn hash_challenge(pp: &PublicParams, y_point: &RistrettoPoint, s_val: &RistrettoPoint, lhs: &RistrettoPoint, comm1: &RistrettoPoint, comm2: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha512::new(); hasher.update(b"NTAT:H2:");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(pp.g2.compress().as_bytes()); bytes.extend_from_slice(y_point.compress().as_bytes());
        bytes.extend_from_slice(s_val.compress().as_bytes()); bytes.extend_from_slice(lhs.compress().as_bytes());
        bytes.extend_from_slice(comm1.compress().as_bytes()); bytes.extend_from_slice(comm2.compress().as_bytes());
        hasher.update(&bytes);
        Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Token { pub sigma: RistrettoPoint }
impl Token { pub fn key(&self) -> [u8; 32] { self.sigma.compress().to_bytes() } }

#[derive(Clone, Serialize, Deserialize)]
pub struct Witness { pub x: Scalar, pub r: Scalar, pub s: Scalar, pub e: u64 }
pub struct IssuanceState { pub r: Scalar, pub delta: Scalar, pub x: RistrettoPoint, pub t: RistrettoPoint, pub e: u64 }

pub fn client_issue_query<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, sk_c: &ClientSecret, pk_s: &ServerPublic, e: u64) -> (RistrettoPoint, ClientProof, IssuanceState) {
    let x_val = sk_c.x; let x = pp.g1 * x_val;
    let r = random_scalar(rng); let delta = random_scalar(rng);
    let c = x + pp.g3 * r + pp.g4 + pp.g_v * Scalar::from(e);
    let t = c * delta;
    let proof = ClientProof::prove(rng, pp, pk_s, x, x_val, r, delta, t);
    let state = IssuanceState { r, delta, x, t, e };
    (t, proof, state)
}

pub fn server_issue_response<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, sk_s: &ServerSecret, pk_c: &ClientPublic, t: &RistrettoPoint, proof: &ClientProof, pk_s: &ServerPublic, e: u64) -> Option<(Scalar, RistrettoPoint, ServerProof)> {
    if !proof.verify(pp, pk_s, &pk_c.x, t, e) { return None; }
    let y = sk_s.y;
    loop {
        let s = random_scalar(rng);
        if (y + s) != Scalar::zero() { // Fix: Scalar::zero() instead of Scalar::ZERO
            let s_val = *t * (y + s).invert();
            let server_proof = ServerProof::prove(rng, pp, y, pk_s.y, s, *t, s_val);
            return Some((s, s_val, server_proof));
        }
    }
}

pub fn client_finalize(pp: &PublicParams, pk_s: &ServerPublic, state: IssuanceState, s: Scalar, s_val: RistrettoPoint, server_proof: &ServerProof, x_val: Scalar) -> Option<(Token, Witness)> {
    if !server_proof.verify(pp, &pk_s.y, s, &state.t, &s_val) { return None; }
    let delta_inv = state.delta.invert();
    let sigma = s_val * delta_inv;
    let witness = Witness { x: x_val, r: state.r, s, e: state.e };
    Some((Token { sigma }, witness))
}

pub type SessionId = u128;

#[derive(Clone, Serialize, Deserialize)]
pub struct RedemptionFirstMessage {
    pub sigma: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub com: RistrettoPoint,
    pub comm: [u8; 32], 
}

pub struct RedemptionState {
    pub rho: [u8; 32], pub v0: Scalar, pub v1: Scalar, pub v2: Scalar, pub v_e: Scalar, pub v_r_com: Scalar,
}

impl RedemptionState {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, token: &Token, witness: &Witness, r_com: Scalar, com: RistrettoPoint) -> (RedemptionFirstMessage, Self) {
        let v0 = random_scalar(rng); let v1 = random_scalar(rng); let v2 = random_scalar(rng);
        let v_e = random_scalar(rng); let v_r_com = random_scalar(rng);
        
        let q_ntat = pp.g1 * v0 + pp.g3 * v1 + pp.g_v * v_e + token.sigma * v2;
        let q_com = pp.g_v * v_e + pp.g_b * v_r_com;

        let mut rho = [0u8; 32]; rng.fill_bytes(&mut rho);
        let mut hasher = Sha512::new(); hasher.update(b"NTAT:H3:BRIDGE"); hasher.update(&rho);
        hasher.update(q_ntat.compress().as_bytes()); hasher.update(q_com.compress().as_bytes()); hasher.update(com.compress().as_bytes());
        
        let comm = hasher.finalize()[..32].try_into().unwrap();
        let first = RedemptionFirstMessage { sigma: token.sigma, com, comm };
        let state = RedemptionState { rho, v0, v1, v2, v_e, v_r_com };
        (first, state)
    }

    pub fn compute_response(&self, challenge: Scalar, witness: &Witness, r_com: Scalar) -> RedemptionResponse {
        RedemptionResponse {
            sid: 0, rho: self.rho,
            z0: self.v0 + challenge * witness.x, z1: self.v1 + challenge * witness.r, z2: self.v2 - challenge * witness.s,
            z_e: self.v_e + challenge * Scalar::from(witness.e), z_r_com: self.v_r_com + challenge * r_com,
            com: RistrettoPoint::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RedemptionResponse {
    pub sid: SessionId, pub rho: [u8; 32], pub z0: Scalar, pub z1: Scalar, pub z2: Scalar, pub z_e: Scalar, pub z_r_com: Scalar,
    #[serde(with = "ristretto_serde")] pub com: RistrettoPoint,
}

pub struct RedemptionSession {
    pub sid: SessionId, pub sigma: RistrettoPoint, pub sigma_prime: RistrettoPoint, pub com: RistrettoPoint, pub comm: [u8; 32], pub challenge: Scalar, pub created_at: SystemTime, token_key: [u8; 32],
}

pub struct RedemptionSessionStore { sessions: RwLock<HashMap<SessionId, RedemptionSession>> }
impl RedemptionSessionStore {
    pub fn new() -> Self { RedemptionSessionStore { sessions: RwLock::new(HashMap::new()) } }
    fn insert(&self, session: RedemptionSession) -> Result<(), ()> {
        let mut map = self.sessions.write().unwrap();
        if map.contains_key(&session.sid) { Err(()) } else { map.insert(session.sid, session); Ok(()) }
    }
    fn take(&self, sid: SessionId) -> Option<RedemptionSession> { self.sessions.write().unwrap().remove(&sid) }
}

pub struct DoubleSpendingSet { used: Mutex<HashSet<[u8; 32]>> }
impl DoubleSpendingSet {
    pub fn new() -> Self { DoubleSpendingSet { used: Mutex::new(HashSet::new()) } }
    pub fn try_use(&self, token: &Token) -> Option<()> {
        let key = token.key(); let mut guard = self.used.lock().unwrap();
        if guard.contains(&key) { None } else { guard.insert(key); Some(()) }
    }
    pub fn release(&self, token: &Token) { self.used.lock().unwrap().remove(&token.key()); }
}

pub fn redemption_server_start<R: RngCore + CryptoRng>(rng: &mut R, pp: &PublicParams, sk_s: &ServerSecret, double_spend: &DoubleSpendingSet, session_store: &RedemptionSessionStore, first: &RedemptionFirstMessage) -> Option<(SessionId, Scalar)> {
    let sigma = first.sigma; let sigma_prime = sigma * sk_s.y; let token = Token { sigma };
    if double_spend.try_use(&token).is_none() { return None; }
    let sid: SessionId = rng.gen(); let challenge = random_scalar(rng);
    let session = RedemptionSession { sid, sigma, sigma_prime, com: first.com, comm: first.comm, challenge, created_at: SystemTime::now(), token_key: token.key() };
    if session_store.insert(session).is_err() { double_spend.release(&token); return None; }
    Some((sid, challenge))
}

pub fn redemption_server_verify(pp: &PublicParams, double_spend: &DoubleSpendingSet, session_store: &RedemptionSessionStore, response: &RedemptionResponse) -> bool {
    let session = match session_store.take(response.sid) { Some(s) => s, None => return false };
    let q_ntat_prime = pp.g1 * response.z0 + pp.g3 * response.z1 + pp.g_v * response.z_e + session.sigma * response.z2 - (session.sigma_prime - pp.g4) * session.challenge;
    let q_com_prime = pp.g_v * response.z_e + pp.g_b * response.z_r_com - session.com * session.challenge;
    let mut hasher = Sha512::new(); hasher.update(b"NTAT:H3:BRIDGE"); hasher.update(&response.rho);
    hasher.update(q_ntat_prime.compress().as_bytes()); hasher.update(q_com_prime.compress().as_bytes()); hasher.update(session.com.compress().as_bytes());
    let comm_prime: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
    if comm_prime != session.comm || response.com != session.com { double_spend.release(&Token { sigma: session.sigma }); return false; }
    true
}
