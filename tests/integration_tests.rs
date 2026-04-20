/// NTAT V2 – Rigorous Integration Test Suite
///
/// Run with:  cargo test -- --nocapture
/// to see all timing and payload-size output.

use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::RngCore;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ntat::base::{
    client_finalize, client_issue_query, server_issue_response, ClientSecret,
    DoubleSpendingSet, PublicParams, RedemptionSessionStore, RedemptionState,
    ServerSecret, Token, Witness,
    redemption_server_start, redemption_server_verify,
};
use ntat::combined::{
    create_combined_redemption, create_combined_redemption_auto,
    verify_combined_redemption, verify_combined_redemption_auto,
};
use ntat::file_binding::{
    auto_challenge_count, auto_block_size, create_file_commitment,
    create_file_commitment_auto, create_file_proof,
    verify_file_proof, FileCommitment, BATCH_THRESHOLD,
};
use ntat::proof::{prove_greater_than, verify as verify_bp};
use ntat::rate_limit::{
    create_rate_limited_redemption, derive_rate_limit_generators,
    verify_rate_limited_proof_only, verify_rate_limited_redemption, RateLimitState,
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Issue a fresh token whose expiry is `offset_secs` ahead of *now*.
fn issue_token(
    rng: &mut OsRng,
    pp: &PublicParams,
    sk_c: &ClientSecret,
    sk_s: &ServerSecret,
    expiry_offset_secs: u64,
) -> (Token, Witness) {
    let pk_c = sk_c.public(pp);
    let pk_s = sk_s.public(pp);
    let expiry = now_secs() + expiry_offset_secs;
    let (t, cp, state) = client_issue_query(rng, pp, sk_c, &pk_s, expiry);
    let (s, s_val, sp) =
        server_issue_response(rng, pp, sk_s, &pk_c, &t, &cp, &pk_s, expiry).unwrap();
    client_finalize(pp, &pk_s, state, s, s_val, &sp, sk_c.x).unwrap()
}

fn fmt_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.2} KB", n as f64 / 1024.0)
    } else {
        format!("{:.2} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn serial_size<T: serde::Serialize>(v: &T) -> usize {
    bincode::serialize(v).unwrap().len()
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 1: Public parameters & key setup
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_setup_is_deterministic() {
    let pp1 = PublicParams::setup();
    let pp2 = PublicParams::setup();
    // Generators must be identical across invocations (derived from fixed seeds)
    assert_eq!(pp1.g1.compress(), pp2.g1.compress());
    assert_eq!(pp1.g2.compress(), pp2.g2.compress());
    assert_eq!(pp1.g3.compress(), pp2.g3.compress());
    assert_eq!(pp1.g4.compress(), pp2.g4.compress());
    println!("[setup] PublicParams is deterministic ✓");
}

#[test]
fn test_key_generation_is_random() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk1 = ClientSecret::new(&mut rng);
    let sk2 = ClientSecret::new(&mut rng);
    // Two independently generated keys must differ
    assert_ne!(sk1.x, sk2.x);
    // Public key matches private key
    let pk1 = sk1.public(&pp);
    assert_eq!(pk1.x, pp.g1 * sk1.x);
    println!("[setup] Key generation randomness ✓");
}

#[test]
fn test_setup_timing_and_sizes() {
    let t = Instant::now();
    let pp = PublicParams::setup();
    let pp_time = t.elapsed();

    let mut rng = OsRng;
    let t = Instant::now();
    let sk_c = ClientSecret::new(&mut rng);
    let _pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let _pk_s = sk_s.public(&pp);
    let key_time = t.elapsed();

    println!("[setup] PublicParams setup:  {:?}", pp_time);
    println!("[setup] Keypair generation:  {:?}", key_time);
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 2: Issuance protocol (blind signing)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_issuance_happy_path() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);
    let expiry = now_secs() + 86400;

    let t0 = Instant::now();
    let (t, client_proof, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);
    let d_client_query = t0.elapsed();

    let t1 = Instant::now();
    let result = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, expiry);
    let d_server = t1.elapsed();
    assert!(result.is_some(), "Server should accept valid client proof");
    let (s, s_val, server_proof) = result.unwrap();

    let t2 = Instant::now();
    let finalize = client_finalize(&pp, &pk_s, state, s, s_val, &server_proof, sk_c.x);
    let d_finalize = t2.elapsed();
    assert!(finalize.is_some(), "Client finalization should succeed");

    let (token, witness) = finalize.unwrap();
    assert_eq!(witness.e, expiry);

    // Sizes
    let cp_size = serial_size(&client_proof);
    let sp_size = serial_size(&server_proof);
    let tok_size = serial_size(&token);
    let wit_size = serial_size(&witness);

    println!("[issuance] client_issue_query :  {:?}  (client_proof = {})", d_client_query, fmt_bytes(cp_size));
    println!("[issuance] server_issue_response: {:?}  (server_proof = {})", d_server, fmt_bytes(sp_size));
    println!("[issuance] client_finalize :     {:?}  (token = {}, witness = {})", d_finalize, fmt_bytes(tok_size), fmt_bytes(wit_size));
}

#[test]
fn test_server_rejects_tampered_client_proof() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);
    let expiry = now_secs() + 86400;

    let (t, mut client_proof, _state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);

    // Corrupt the challenge scalar
    let bad_bytes = [0xFF_u8; 32];
    client_proof.ch = Scalar::from_bytes_mod_order(bad_bytes);

    let result = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, expiry);
    assert!(result.is_none(), "Server must reject tampered client proof");
    println!("[issuance] Tampered client proof rejected ✓");
}

#[test]
fn test_server_rejects_wrong_expiry() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);
    let expiry = now_secs() + 86400;
    let wrong_expiry = now_secs() + 999999;

    let (t, client_proof, _state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);

    // Server verifies with a different expiry value → proof should not verify
    let result = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, wrong_expiry);
    assert!(result.is_none(), "Server must reject proof with wrong expiry");
    println!("[issuance] Wrong expiry rejected ✓");
}

#[test]
fn test_client_rejects_tampered_server_proof() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);
    let expiry = now_secs() + 86400;

    let (t, client_proof, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);
    let (s, s_val, mut server_proof) =
        server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, expiry).unwrap();

    // Corrupt server proof challenge
    server_proof.ch = Scalar::from_bytes_mod_order([0xAB_u8; 32]);
    let result = client_finalize(&pp, &pk_s, state, s, s_val, &server_proof, sk_c.x);
    assert!(result.is_none(), "Client must reject tampered server proof");
    println!("[issuance] Tampered server proof rejected ✓");
}

#[test]
fn test_different_server_key_rejected() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);
    // A completely different server key
    let sk_s2 = ServerSecret::new(&mut rng);
    let expiry = now_secs() + 86400;

    let (t, client_proof, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);
    // Server signs with sk_s
    let (s, s_val, server_proof) =
        server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, expiry).unwrap();

    // Client verifies against pk_s2 (wrong public key) → should fail
    let pk_s2 = sk_s2.public(&pp);
    let result = client_finalize(&pp, &pk_s2, state, s, s_val, &server_proof, sk_c.x);
    assert!(result.is_none(), "Client must reject proof from wrong server key");
    println!("[issuance] Wrong server key rejected ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 3: Two-round redemption (base protocol)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_base_redemption_happy_path() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let r_com = Scalar::zero();
    // com must equal g_v * e + g_b * r_com so the ZK bridge verifies
    let com = pp.g_v * Scalar::from(witness.e) + pp.g_b * r_com;
    let t0 = Instant::now();
    let (first, state) = RedemptionState::new(&mut rng, &pp, &token, &witness, r_com, com);
    let d_client_start = t0.elapsed();

    let ds = DoubleSpendingSet::new();
    let store = RedemptionSessionStore::new();

    // Server start
    let t1 = Instant::now();
    let result = redemption_server_start(&mut rng, &pp, &sk_s, &ds, &store, &first);
    let d_server_start = t1.elapsed();
    assert!(result.is_some(), "Server start should succeed for valid token");
    let (sid, challenge) = result.unwrap();

    // Client responds
    let t2 = Instant::now();
    let mut response = state.compute_response(challenge, &witness, r_com);
    response.sid = sid;
    response.com = com;
    let d_client_resp = t2.elapsed();

    // Server verifies
    let t3 = Instant::now();
    let valid = redemption_server_verify(&pp, &ds, &store, &response);
    let d_server_verify = t3.elapsed();
    assert!(valid, "Base redemption verification should succeed");

    println!("[redemption] client_start:   {:?}", d_client_start);
    println!("[redemption] server_start:   {:?}", d_server_start);
    println!("[redemption] client_respond: {:?}", d_client_resp);
    println!("[redemption] server_verify:  {:?}", d_server_verify);
    println!("[redemption] first_msg size: {}", fmt_bytes(serial_size(&first)));
    println!("[redemption] response size:  {}", fmt_bytes(serial_size(&response)));
}

#[test]
fn test_base_redemption_double_spend_blocked() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, _witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let ds = DoubleSpendingSet::new();
    // Mark token as used
    assert!(ds.try_use(&token).is_some(), "First use should succeed");
    // Second use must be blocked
    assert!(ds.try_use(&token).is_none(), "Double spend must be blocked");
    println!("[redemption] Double spend via DoubleSpendingSet blocked ✓");
}

#[test]
fn test_base_redemption_second_attempt_blocked() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let r_com = Scalar::zero();
    let com = RistrettoPoint::default();

    let ds = DoubleSpendingSet::new();
    let store = RedemptionSessionStore::new();

    let (first, _state) = RedemptionState::new(&mut rng, &pp, &token, &witness, r_com, com);
    let res1 = redemption_server_start(&mut rng, &pp, &sk_s, &ds, &store, &first);
    assert!(res1.is_some(), "First session start should succeed");

    // Attempt to start a second session for the same token (same sigma in first msg)
    let (first2, _state2) = RedemptionState::new(&mut rng, &pp, &token, &witness, r_com, com);
    let res2 = redemption_server_start(&mut rng, &pp, &sk_s, &ds, &store, &first2);
    assert!(res2.is_none(), "Second redemption attempt for same token must be blocked");
    println!("[redemption] Concurrent double-spend session blocked ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 4: Rate-limiting
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rate_limit_generators_are_unique() {
    let gens = derive_rate_limit_generators(1, b"app", 8);
    for i in 0..gens.len() {
        for j in (i + 1)..gens.len() {
            assert_ne!(gens[i].compress(), gens[j].compress(), "Generators must be unique");
        }
    }
    println!("[rate_limit] All generators are distinct ✓");
}

#[test]
fn test_rate_limit_different_epochs_differ() {
    let g_e1 = derive_rate_limit_generators(1, b"app", 4);
    let g_e2 = derive_rate_limit_generators(2, b"app", 4);
    for (a, b) in g_e1.iter().zip(g_e2.iter()) {
        assert_ne!(a.compress(), b.compress());
    }
    println!("[rate_limit] Different epochs produce different generators ✓");
}

#[test]
fn test_rate_limit_proof_valid() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let state = RateLimitState::new(7, b"test_app".to_vec(), 16);
    let slot = 3;
    let r_com = Scalar::zero();
    // com must equal g_v * e + g_b * r_com for the ZK bridge to verify
    let com = pp.g_v * Scalar::from(witness.e) + pp.g_b * r_com;

    let t0 = Instant::now();
    let (proof, _tag) = create_rate_limited_redemption(&mut rng, &pp, &token, &witness, &state, slot, r_com, com);
    let d_prove = t0.elapsed();

    let t1 = Instant::now();
    let valid = verify_rate_limited_proof_only(&pp, &sk_s, &proof, &state);
    let d_verify = t1.elapsed();

    assert!(valid, "Rate limit proof should verify");
    println!("[rate_limit] proof gen:    {:?}  (size = {})", d_prove, fmt_bytes(serial_size(&proof)));
    println!("[rate_limit] proof verify: {:?}", d_verify);
}

#[test]
fn test_rate_limit_double_use_blocked() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let state = RateLimitState::new(7, b"test_app".to_vec(), 8);
    let slot = 2;
    let r_com = Scalar::zero();
    // com must equal g_v * e + g_b * r_com for the ZK bridge to verify
    let com = pp.g_v * Scalar::from(witness.e) + pp.g_b * r_com;

    let (proof, _) = create_rate_limited_redemption(&mut rng, &pp, &token, &witness, &state, slot, r_com, com);

    let v1 = verify_rate_limited_redemption(&pp, &sk_s, &proof, &state);
    assert!(v1, "First use should succeed");
    let v2 = verify_rate_limited_redemption(&pp, &sk_s, &proof, &state);
    assert!(!v2, "Rate-limit double-use must be blocked");
    println!("[rate_limit] Double-use blocked ✓");
}

#[test]
fn test_rate_limit_wrong_server_key() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let sk_s_bad = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    let state = RateLimitState::new(1, b"app".to_vec(), 8);
    let r_com = Scalar::zero();
    let com = pp.g_v * Scalar::from(witness.e) + pp.g_b * r_com;
    let (proof, _) = create_rate_limited_redemption(&mut rng, &pp, &token, &witness, &state, 0, r_com, com);

    let valid = verify_rate_limited_proof_only(&pp, &sk_s_bad, &proof, &state);
    assert!(!valid, "Wrong server key must cause rate-limit proof to fail");
    println!("[rate_limit] Wrong server key rejected ✓");
}

#[test]
fn test_rate_limit_proof_sizes_for_different_slot_counts() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    println!("[rate_limit] Proof sizes by slot count:");
    for &n in &[4usize, 8, 16, 32, 64, 128, 256] {
        let state = RateLimitState::new(1, b"app".to_vec(), n);
        let slot = n / 2;
        let r_com = Scalar::zero();
        let com = pp.g_v * Scalar::from(witness.e) + pp.g_b * r_com;
        let t = Instant::now();
        let (proof, _) = create_rate_limited_redemption(
            &mut rng, &pp, &token, &witness, &state, slot, r_com, com,
        );
        let d = t.elapsed();
        let valid = verify_rate_limited_proof_only(&pp, &sk_s, &proof, &state);
        assert!(valid);
        println!("  n={:>4}  gen={:>8?}  size={}", n, d, fmt_bytes(serial_size(&proof)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 5: File binding (commitment + proof)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_file_commitment_basic() {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [1u8; 32];
    let blocks: Vec<Vec<u8>> = vec![
        b"block_zero_data".to_vec(),
        b"block_one_data!".to_vec(),
        b"block_two_data_".to_vec(),
    ];

    let t = Instant::now();
    let (commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);
    let d = t.elapsed();

    assert_eq!(commitment.file_id, file_id);
    assert_eq!(commitment.num_blocks, 3);
    assert_eq!(ciphertexts.len(), 3);
    assert_eq!(leaves.len(), 3);

    println!("[file_binding] Commitment gen (3 blocks): {:?}  size={}", d, fmt_bytes(serial_size(&commitment)));
}

#[test]
fn test_file_commitment_is_deterministic_for_same_nonce() {
    // Two commitments of the same file must share the same root (up to the
    // random encryption nonce embedded in the commitment – so roots will differ,
    // but file_id / num_blocks / block_size must match).
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [2u8; 32];
    let blocks: Vec<Vec<u8>> = vec![b"data_block".to_vec()];

    let (c1, _, _) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);
    let (c2, _, _) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    assert_eq!(c1.file_id, c2.file_id);
    assert_eq!(c1.num_blocks, c2.num_blocks);
    assert_eq!(c1.block_size, c2.block_size);
    println!("[file_binding] Deterministic metadata across re-commitments ✓");
}

#[test]
fn test_auto_block_size_scaling() {
    let cases = [
        (1_024usize, 256usize),           // 1 KB  → clamped to MIN_BLOCK_SIZE (256)
        (1_024 * 1_024, 1906),            // 1 MB  → 1048576/550 = 1906
        (100 * 1_024 * 1_024, 65536),     // 100 MB → clamped to MAX_BLOCK_SIZE (65536)
    ];
    for (file_size, expected) in cases {
        let got = auto_block_size(file_size);
        assert_eq!(got, expected, "file_size={} expected block_size={} got={}", file_size, expected, got);
    }
    println!("[file_binding] auto_block_size scaling ✓");
}

#[test]
fn test_auto_challenge_count_scaling() {
    // More blocks → more challenges (up to the 100-cap)
    let c10  = auto_challenge_count(10,   0.95);
    let c100 = auto_challenge_count(100,  0.95);
    let c1k  = auto_challenge_count(1000, 0.95);
    assert!(c10  >= 10);
    assert!(c100 >= c10);
    assert_eq!(c1k, 100, "Should be capped at 100");
    println!("[file_binding] auto_challenge_count: n=10→{}, n=100→{}, n=1000→{}", c10, c100, c1k);
}

#[test]
fn test_file_proof_single_dleq() {
    // Use < BATCH_THRESHOLD (3) challenges → individual DLEQ proofs per block
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [3u8; 32];
    // Need at least 2 blocks, use 2 challenges (< BATCH_THRESHOLD=3)
    let blocks: Vec<Vec<u8>> = vec![b"alpha".to_vec(), b"beta_".to_vec(), b"gamma".to_vec()];
    let (commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 4)[0];
    let tag = slot_gen * sk_c.x;
    let challenge_nonce = [0u8; 32];
    let num_challenges = 2; // < BATCH_THRESHOLD

    let t = Instant::now();
    let proof = create_file_proof(
        &mut rng, &sk_c.x, file_id, &ciphertexts, &leaves,
        &commitment.root_hash, &challenge_nonce, num_challenges, &slot_gen, &tag,
    );
    let d = t.elapsed();

    assert!(proof.batch_proof.is_none(), "Should use individual DLEQ proofs");
    assert_eq!(proof.blocks.len(), 2);

    let t2 = Instant::now();
    let valid = verify_file_proof(&proof, &commitment, &challenge_nonce, &slot_gen, &tag);
    let d2 = t2.elapsed();
    assert!(valid, "File proof (single DLEQ) must verify");

    println!("[file_binding] Single-DLEQ file proof  gen={:?}  verify={:?}  size={}", d, d2, fmt_bytes(serial_size(&proof)));
}

#[test]
fn test_file_proof_batch_dleq() {
    // >= BATCH_THRESHOLD challenges → batched DLEQ proof
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [4u8; 32];
    let blocks: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 64]).collect();
    let (commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 4)[1];
    let tag = slot_gen * sk_c.x;
    let challenge_nonce = [1u8; 32];
    let num_challenges = BATCH_THRESHOLD; // triggers batch path

    let t = Instant::now();
    let proof = create_file_proof(
        &mut rng, &sk_c.x, file_id, &ciphertexts, &leaves,
        &commitment.root_hash, &challenge_nonce, num_challenges, &slot_gen, &tag,
    );
    let d = t.elapsed();

    assert!(proof.batch_proof.is_some(), "Should use batched DLEQ proof");

    let t2 = Instant::now();
    let valid = verify_file_proof(&proof, &commitment, &challenge_nonce, &slot_gen, &tag);
    let d2 = t2.elapsed();
    assert!(valid, "File proof (batch DLEQ) must verify");

    println!("[file_binding] Batch-DLEQ file proof   gen={:?}  verify={:?}  size={}", d, d2, fmt_bytes(serial_size(&proof)));
}

#[test]
fn test_file_proof_wrong_root_hash_rejected() {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [5u8; 32];
    let blocks: Vec<Vec<u8>> = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];
    let (mut commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 2)[0];
    let tag = slot_gen * sk_c.x;
    let nonce = [2u8; 32];

    let proof = create_file_proof(&mut rng, &sk_c.x, file_id, &ciphertexts, &leaves, &commitment.root_hash, &nonce, 2, &slot_gen, &tag);

    // Corrupt the stored root
    commitment.root_hash[0] ^= 0xFF;
    let valid = verify_file_proof(&proof, &commitment, &nonce, &slot_gen, &tag);
    assert!(!valid, "Wrong root hash must be rejected");
    println!("[file_binding] Corrupted root hash rejected ✓");
}

#[test]
fn test_file_proof_wrong_file_id_rejected() {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let file_id = [6u8; 32];
    let wrong_id = [0u8; 32];
    let blocks: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
    let (commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 2)[0];
    let tag = slot_gen * sk_c.x;
    let nonce = [3u8; 32];

    // proof records the real file_id
    let proof = create_file_proof(&mut rng, &sk_c.x, file_id, &ciphertexts, &leaves, &commitment.root_hash, &nonce, 1, &slot_gen, &tag);

    // Build a fake commitment that uses the wrong file_id
    let fake_commitment = FileCommitment { file_id: wrong_id, ..commitment };
    let valid = verify_file_proof(&proof, &fake_commitment, &nonce, &slot_gen, &tag);
    assert!(!valid, "Wrong file_id must be rejected");
    println!("[file_binding] Wrong file_id rejected ✓");
}

#[test]
fn test_file_proof_wrong_tag_rejected() {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let sk_other = ClientSecret::new(&mut rng);
    let file_id = [7u8; 32];
    let blocks: Vec<Vec<u8>> = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec()];
    let (commitment, ciphertexts, leaves) = create_file_commitment(&mut rng, file_id, &blocks, &sk_c.x);

    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 2)[0];
    let tag = slot_gen * sk_c.x;
    let wrong_tag = slot_gen * sk_other.x; // different client key
    let nonce = [4u8; 32];

    let proof = create_file_proof(&mut rng, &sk_c.x, file_id, &ciphertexts, &leaves, &commitment.root_hash, &nonce, BATCH_THRESHOLD, &slot_gen, &tag);
    let valid = verify_file_proof(&proof, &commitment, &nonce, &slot_gen, &wrong_tag);
    assert!(!valid, "Wrong tag must be rejected");
    println!("[file_binding] Wrong tag rejected ✓");
}

#[test]
fn test_file_proof_sizes_for_different_file_sizes() {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let slot_gen = derive_rate_limit_generators(1, b"app".to_vec().as_slice(), 2)[0];
    let nonce = [5u8; 32];

    println!("[file_binding] File proof sizes by file size:");
    for &kb in &[4usize, 16, 64, 256, 1024] {
        let mut data = vec![0u8; kb * 1024];
        rng.fill_bytes(&mut data);
        let file_id = [kb as u8; 32];

        let t0 = Instant::now();
        let (comm, ct, leaves) = create_file_commitment_auto(&mut rng, file_id, &data, &sk_c.x);
        let d_comm = t0.elapsed();

        let tag = slot_gen * sk_c.x;
        let n_challenges = auto_challenge_count(comm.num_blocks, 0.99).min(comm.num_blocks as usize);

        let t1 = Instant::now();
        let proof = create_file_proof(&mut rng, &sk_c.x, file_id, &ct, &leaves, &comm.root_hash, &nonce, n_challenges, &slot_gen, &tag);
        let d_proof = t1.elapsed();

        let t2 = Instant::now();
        let valid = verify_file_proof(&proof, &comm, &nonce, &slot_gen, &tag);
        let d_verify = t2.elapsed();
        assert!(valid);

        println!(
            "  {:>5} KB  blocks={:>4}  challenges={:>3}  commit={:>8?}  prove={:>8?}  verify={:>8?}  file_proof={}  commitment={}",
            kb, comm.num_blocks, n_challenges, d_comm, d_proof, d_verify,
            fmt_bytes(serial_size(&proof)), fmt_bytes(serial_size(&comm)),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 6: Bulletproof range proof
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_bulletproof_valid_range() {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let ctx = b"test_context";
    let e = now_secs() + 3600;
    let t_now = now_secs();

    let t = Instant::now();
    let (data, bit_size, _r_com) = prove_greater_than(&bp_gens, &pc_gens, e, t_now, ctx);
    let d_prove = t.elapsed();

    let t2 = Instant::now();
    let valid = verify_bp(&bp_gens, &pc_gens, &data, ctx);
    let d_verify = t2.elapsed();

    assert!(valid, "Range proof must verify for valid token");
    println!("[bulletproof] prove={:?}  verify={:?}  proof_bytes={}  bit_size={}", d_prove, d_verify, fmt_bytes(data.proof.to_bytes().len()), bit_size);
}

#[test]
fn test_bulletproof_wrong_context_rejected() {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let e = now_secs() + 3600;
    let t_now = now_secs();

    let (data, _, _) = prove_greater_than(&bp_gens, &pc_gens, e, t_now, b"ctx_A");
    let valid = verify_bp(&bp_gens, &pc_gens, &data, b"ctx_B");
    assert!(!valid, "Bulletproof must fail with wrong context_id");
    println!("[bulletproof] Wrong context rejected ✓");
}

#[test]
fn test_bulletproof_expired_token_panics() {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let e = now_secs() - 1; // expired
    let t_now = now_secs();

    let result = std::panic::catch_unwind(|| {
        prove_greater_than(&bp_gens, &pc_gens, e, t_now, b"ctx")
    });
    assert!(result.is_err(), "prove_greater_than must panic for expired token (e <= time)");
    println!("[bulletproof] Expired token panics in prover ✓");
}

#[test]
fn test_bulletproof_tampered_commitment_rejected() {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let e = now_secs() + 3600;
    let t_now = now_secs();
    let ctx = b"ctx";

    let (mut data, _, _) = prove_greater_than(&bp_gens, &pc_gens, e, t_now, ctx);
    // Flip a byte in the commitment
    let mut raw = data.commitment.to_bytes();
    raw[0] ^= 0xFF;
    data.commitment = curve25519_dalek_ng::ristretto::CompressedRistretto(raw);

    let valid = verify_bp(&bp_gens, &pc_gens, &data, ctx);
    assert!(!valid, "Tampered commitment must be rejected");
    println!("[bulletproof] Tampered commitment rejected ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 7: Combined redemption proof (full end-to-end)
// ─────────────────────────────────────────────────────────────────────────────

fn make_combined_setup(
    rng: &mut OsRng,
    file_kb: usize,
) -> (
    PublicParams,
    ClientSecret,
    ServerSecret,
    Token,
    Witness,
    RateLimitState,
    usize, // slot
    [u8; 32], // file_id
    Vec<ntat::file_binding::CiphertextBlock>,
    Vec<[u8; 32]>,
    ntat::file_binding::FileCommitment,
    BulletproofGens,
    PedersenGens,
) {
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(rng);
    let sk_s = ServerSecret::new(rng);
    let (token, witness) = issue_token(rng, &pp, &sk_c, &sk_s, 86400);

    let mut data = vec![0u8; file_kb * 1024];
    rng.fill_bytes(&mut data);
    let file_id = [0xABu8; 32];
    let (file_comm, ct, leaves) = create_file_commitment_auto(rng, file_id, &data, &sk_c.x);

    let rate_state = RateLimitState::new(42, b"combined_test".to_vec(), 64);
    let slot = 31;

    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();

    (pp, sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens)
}

#[test]
fn test_combined_proof_happy_path_small_file() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 16);

    let nonce = [0u8; 32];
    let n_challenges = auto_challenge_count(file_comm.num_blocks, 0.95).min(file_comm.num_blocks as usize);
    let ctx = b"happy_path";
    let t_now = now_secs();

    let t0 = Instant::now();
    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash,
        nonce, n_challenges, t_now, &bp_gens, &pc_gens, ctx,
    );
    let d_prove = t0.elapsed();

    let t1 = Instant::now();
    let valid = verify_combined_redemption(
        &pp, &sk_s, &proof, &rate_state, &file_comm, slot,
        t_now, &bp_gens, &pc_gens, ctx,
    );
    let d_verify = t1.elapsed();

    assert!(valid, "Combined proof must verify on happy path");

    println!("[combined] 16 KB  prove={:?}  verify={:?}", d_prove, d_verify);
    println!("  total payload   : {}", fmt_bytes(serial_size(&proof)));
    println!("  ├─ rate_proof   : {}", fmt_bytes(serial_size(&proof.rate_proof)));
    println!("  ├─ file_proof   : {}", fmt_bytes(serial_size(&proof.file_proof)));
    println!("  └─ bp_data      : {}", fmt_bytes(proof.bp_data.proof.to_bytes().len()));
}

#[test]
fn test_combined_double_spend_blocked() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 4);

    let nonce = [0u8; 32];
    let n = auto_challenge_count(file_comm.num_blocks, 0.90).min(file_comm.num_blocks as usize);
    let ctx = b"double_spend_test";
    let t_now = now_secs();

    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, ctx,
    );

    let v1 = verify_combined_redemption(&pp, &sk_s, &proof, &rate_state, &file_comm, slot, t_now, &bp_gens, &pc_gens, ctx);
    assert!(v1, "First verification should succeed");

    let v2 = verify_combined_redemption(&pp, &sk_s, &proof, &rate_state, &file_comm, slot, t_now, &bp_gens, &pc_gens, ctx);
    assert!(!v2, "Replay must be blocked");
    println!("[combined] Double-spend blocked ✓");
}

#[test]
fn test_combined_wrong_server_key_rejected() {
    let mut rng = OsRng;
    let (pp, _sk_c, _sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 4);

    let sk_s_bad = ServerSecret::new(&mut rng);
    let nonce = [0u8; 32];
    let n = auto_challenge_count(file_comm.num_blocks, 0.90).min(file_comm.num_blocks as usize);
    let ctx = b"wrong_key_test";
    let t_now = now_secs();

    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, ctx,
    );

    let valid = verify_combined_redemption(&pp, &sk_s_bad, &proof, &rate_state, &file_comm, slot, t_now, &bp_gens, &pc_gens, ctx);
    assert!(!valid, "Wrong server key must fail");
    println!("[combined] Wrong server key rejected ✓");
}

#[test]
fn test_combined_wrong_slot_rejected() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 4);

    let nonce = [0u8; 32];
    let n = auto_challenge_count(file_comm.num_blocks, 0.90).min(file_comm.num_blocks as usize);
    let ctx = b"wrong_slot_test";
    let t_now = now_secs();

    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, ctx,
    );

    let wrong_slot = (slot + 1) % 64;
    let valid = verify_combined_redemption(&pp, &sk_s, &proof, &rate_state, &file_comm, wrong_slot, t_now, &bp_gens, &pc_gens, ctx);
    assert!(!valid, "Wrong slot must fail file proof verification");
    println!("[combined] Wrong slot rejected ✓");
}

#[test]
fn test_combined_wrong_context_rejected() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 4);

    let nonce = [0u8; 32];
    let n = auto_challenge_count(file_comm.num_blocks, 0.90).min(file_comm.num_blocks as usize);
    let t_now = now_secs();

    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, b"ctx_A",
    );

    let valid = verify_combined_redemption(&pp, &sk_s, &proof, &rate_state, &file_comm, slot, t_now, &bp_gens, &pc_gens, b"ctx_B");
    assert!(!valid, "Wrong context must fail bulletproof");
    println!("[combined] Wrong context_id rejected ✓");
}

#[test]
fn test_combined_expired_token_panics_at_prove() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);

    // Issue a token that was already expired
    let expired_expiry = now_secs() - 1;
    let pk_c = sk_c.public(&pp);
    let pk_s = sk_s.public(&pp);
    let (t, cp, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expired_expiry);
    let (s, s_val, sp) = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &cp, &pk_s, expired_expiry).unwrap();
    let (token, witness) = client_finalize(&pp, &pk_s, state, s, s_val, &sp, sk_c.x).unwrap();

    let rate_state = RateLimitState::new(1, b"app".to_vec(), 4);
    let blocks: Vec<Vec<u8>> = vec![b"data".to_vec()];
    let (fc, ct, leaves) = create_file_commitment(&mut rng, [0u8; 32], &blocks, &witness.x);

    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();

    let result = std::panic::catch_unwind(|| {
        let mut rng2 = OsRng;
        let t_now = now_secs();
        create_combined_redemption(
            &mut rng2, &pp, &token, &witness, &rate_state, 0,
            [0u8; 32], &ct, &leaves, &fc.root_hash,
            [0u8; 32], 1, t_now, &bp_gens, &pc_gens, b"ctx",
        )
    });
    assert!(result.is_err(), "Expired token must panic in combined prover");
    println!("[combined] Expired token panics at prove ✓");
}

#[test]
fn test_combined_wrong_file_commitment_rejected() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 4);

    let nonce = [0u8; 32];
    let n = auto_challenge_count(file_comm.num_blocks, 0.90).min(file_comm.num_blocks as usize);
    let ctx = b"wrong_file";
    let t_now = now_secs();

    let proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, ctx,
    );

    // Build a fake commitment for a different file
    let mut fake_comm = file_comm.clone();
    fake_comm.root_hash[0] ^= 0xFF;

    let valid = verify_combined_redemption(&pp, &sk_s, &proof, &rate_state, &fake_comm, slot, t_now, &bp_gens, &pc_gens, ctx);
    assert!(!valid, "Wrong file commitment must be rejected");
    println!("[combined] Tampered file commitment rejected ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 8: Auto-confidence variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_combined_auto_confidence_happy_path() {
    let mut rng = OsRng;
    let (pp, _sk_c, sk_s, token, witness, rate_state, slot, file_id, ct, leaves, file_comm, bp_gens, pc_gens) =
        make_combined_setup(&mut rng, 256); // >=100 blocks needed for verify_combined_redemption_auto

    let nonce = [0u8; 32];
    let confidence = 0.99;
    let ctx = b"auto_confidence";
    let t_now = now_secs();

    let proof = create_combined_redemption_auto(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, confidence,
        t_now, &bp_gens, &pc_gens, ctx,
    );

    let valid = verify_combined_redemption_auto(
        &pp, &sk_s, &proof, &rate_state, &file_comm, slot, confidence,
        t_now, &bp_gens, &pc_gens, ctx,
    );
    assert!(valid, "Auto-confidence combined proof must verify");
    println!("[combined] Auto-confidence (99%) ✓");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 9: Comprehensive payload size & timing profile
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_payload_size_and_timing_profile() {
    let mut rng = OsRng;
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           NTAT V2 – FULL PROFILER (cargo test --nocapture)  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── Setup ──────────────────────────────────────────────────────────────
    let t = Instant::now();
    let pp = PublicParams::setup();
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let d_setup = t.elapsed();

    let t = Instant::now();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let pk_s = sk_s.public(&pp);
    let d_keys = t.elapsed();

    println!("━━ SETUP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  PublicParams::setup  : {:?}", d_setup);
    println!("  Key generation       : {:?}", d_keys);

    // ── Issuance ───────────────────────────────────────────────────────────
    let expiry = now_secs() + 30 * 24 * 3600;

    let t = Instant::now();
    let (blind_t, cp, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);
    let d_cq = t.elapsed();

    let t = Instant::now();
    let (s, s_val, sp) = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &blind_t, &cp, &pk_s, expiry).unwrap();
    let d_sr = t.elapsed();

    let t = Instant::now();
    let (token, witness) = client_finalize(&pp, &pk_s, state, s, s_val, &sp, sk_c.x).unwrap();
    let d_fin = t.elapsed();

    println!("\n━━ ISSUANCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  client_issue_query    : {:?}  client_proof={}", d_cq,  fmt_bytes(serial_size(&cp)));
    println!("  server_issue_response : {:?}  server_proof={}", d_sr,  fmt_bytes(serial_size(&sp)));
    println!("  client_finalize       : {:?}  token={}  witness={}", d_fin, fmt_bytes(serial_size(&token)), fmt_bytes(serial_size(&witness)));

    // ── Rate limit setup ───────────────────────────────────────────────────
    let t = Instant::now();
    let rate_state = RateLimitState::new(1001, b"global_storage".to_vec(), 256);
    let d_rs = t.elapsed();
    println!("\n━━ RATE LIMIT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  RateLimitState::new (256 slots) : {:?}", d_rs);

    // ── File commitment (256 KB) ───────────────────────────────────────────
    let file_kb = 256;
    let mut file_data = vec![0u8; file_kb * 1024];
    rng.fill_bytes(&mut file_data);
    let file_id = [0xDEu8; 32];

    let t = Instant::now();
    let (file_comm, ct, leaves) = create_file_commitment_auto(&mut rng, file_id, &file_data, &sk_c.x);
    let d_fc = t.elapsed();

    println!("\n━━ FILE COMMITMENT ({} KB) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", file_kb);
    println!("  commitment gen  : {:?}", d_fc);
    println!("  blocks          : {}  block_size={} B", file_comm.num_blocks, file_comm.block_size);
    println!("  commitment size : {}", fmt_bytes(serial_size(&file_comm)));
    println!("  ciphertexts     : {}", fmt_bytes(serial_size(&ct)));

    // ── Bulletproof ────────────────────────────────────────────────────────
    let t_now = now_secs();
    let t = Instant::now();
    let (bp_data, _, _) = prove_greater_than(&bp_gens, &pc_gens, expiry, t_now, b"profiler");
    let d_bp = t.elapsed();
    let t = Instant::now();
    assert!(verify_bp(&bp_gens, &pc_gens, &bp_data, b"profiler"));
    let d_bpv = t.elapsed();
    println!("\n━━ BULLETPROOF ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  prove   : {:?}  size={}", d_bp,  fmt_bytes(bp_data.proof.to_bytes().len()));
    println!("  verify  : {:?}", d_bpv);

    // ── Combined proof ─────────────────────────────────────────────────────
    let slot = 128;
    let nonce = [0xFFu8; 32];
    let confidence = 0.99;
    let n_challenges = auto_challenge_count(file_comm.num_blocks, confidence).min(file_comm.num_blocks as usize);
    let ctx = b"profiler_context";

    let t = Instant::now();
    let combined = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ct, &leaves, &file_comm.root_hash, nonce, n_challenges,
        t_now, &bp_gens, &pc_gens, ctx,
    );
    let d_cp = t.elapsed();

    let t = Instant::now();
    let valid = verify_combined_redemption(
        &pp, &sk_s, &combined, &rate_state, &file_comm, slot,
        t_now, &bp_gens, &pc_gens, ctx,
    );
    let d_cv = t.elapsed();
    assert!(valid);

    println!("\n━━ COMBINED REDEMPTION PROOF ({} KB, {}% confidence, {} challenges) ━━", file_kb, (confidence * 100.0) as u8, n_challenges);
    println!("  prove   : {:?}", d_cp);
    println!("  verify  : {:?}", d_cv);
    println!("  payload breakdown:");
    println!("    total         : {}", fmt_bytes(serial_size(&combined)));
    println!("    ├─ rate_proof : {}", fmt_bytes(serial_size(&combined.rate_proof)));
    println!("    ├─ file_proof : {}", fmt_bytes(serial_size(&combined.file_proof)));
    println!("    └─ bp_data    : {}", fmt_bytes(combined.bp_data.proof.to_bytes().len()));

    // ── Double-spend ───────────────────────────────────────────────────────
    let t = Instant::now();
    let v2 = verify_combined_redemption(
        &pp, &sk_s, &combined, &rate_state, &file_comm, slot,
        t_now, &bp_gens, &pc_gens, ctx,
    );
    let d_replay = t.elapsed();
    assert!(!v2, "Replay must be blocked");
    println!("\n━━ DOUBLE-SPEND CHECK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Replay blocked in {:?} ✓", d_replay);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  All assertions passed ✓                                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 10: Cross-component payload size sweep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_combined_proof_sizes_across_file_sizes() {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_token(&mut rng, &pp, &sk_c, &sk_s, 86400);

    println!("[combined] Proof size sweep by file size:");
    println!("{:>8}  {:>6}  {:>5}  {:>8}  {:>8}  {:>10}  {:>10}  {:>10}  {:>10}",
        "file_KB", "blocks", "chal", "prove", "verify", "total", "rate_pf", "file_pf", "bp");

    for &kb in &[4usize, 16, 64, 256] {
        let mut data = vec![0u8; kb * 1024];
        rng.fill_bytes(&mut data);
        let file_id = [kb as u8; 32];
        let (fc, ct, leaves) = create_file_commitment_auto(&mut rng, file_id, &data, &sk_c.x);
        let rate_state = RateLimitState::new(1, b"app".to_vec(), 64);
        let slot = 32;
        let nonce = [0u8; 32];
        let n = auto_challenge_count(fc.num_blocks, 0.99).min(fc.num_blocks as usize);
        let t_now = now_secs();
        let ctx = b"sweep";

        let t0 = Instant::now();
        let proof = create_combined_redemption(
            &mut rng, &pp, &token, &witness, &rate_state, slot,
            file_id, &ct, &leaves, &fc.root_hash, nonce, n, t_now, &bp_gens, &pc_gens, ctx,
        );
        let d_prove = t0.elapsed();

        let t1 = Instant::now();
        let valid = verify_combined_redemption(
            &pp, &sk_s, &proof, &rate_state, &fc, slot, t_now, &bp_gens, &pc_gens, ctx,
        );
        let d_verify = t1.elapsed();
        assert!(valid);

        println!("{:>8}  {:>6}  {:>5}  {:>8?}  {:>8?}  {:>10}  {:>10}  {:>10}  {:>10}",
            kb, fc.num_blocks, n, d_prove, d_verify,
            fmt_bytes(serial_size(&proof)),
            fmt_bytes(serial_size(&proof.rate_proof)),
            fmt_bytes(serial_size(&proof.file_proof)),
            fmt_bytes(proof.bp_data.proof.to_bytes().len()),
        );
    }
}
