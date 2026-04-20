/// Criterion benchmarks for NTAT V2
///
/// Run with:  cargo bench
/// HTML report is written to target/criterion/

use bulletproofs::{BulletproofGens, PedersenGens};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

use ntat::base::{
    client_finalize, client_issue_query, server_issue_response, ClientSecret, PublicParams,
    ServerSecret, Token, Witness,
};
use ntat::combined::{create_combined_redemption, verify_combined_redemption};
use ntat::file_binding::{
    auto_challenge_count, create_file_commitment_auto, create_file_proof, verify_file_proof,
};
use ntat::proof::{prove_greater_than, verify as verify_bp};
use ntat::rate_limit::{
    create_rate_limited_redemption, derive_rate_limit_generators,
    verify_rate_limited_proof_only, RateLimitState,
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

fn issue_fresh_token(
    rng: &mut OsRng,
    pp: &PublicParams,
    sk_c: &ClientSecret,
    sk_s: &ServerSecret,
) -> (Token, Witness) {
    let pk_c = sk_c.public(pp);
    let pk_s = sk_s.public(pp);
    let expiry = now_secs() + 86400;
    let (t, cp, state) = client_issue_query(rng, pp, sk_c, &pk_s, expiry);
    let (s, s_val, sp) =
        server_issue_response(rng, pp, sk_s, &pk_c, &t, &cp, &pk_s, expiry).unwrap();
    client_finalize(pp, &pk_s, state, s, s_val, &sp, sk_c.x).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. System setup
// ─────────────────────────────────────────────────────────────────────────────

fn bench_setup(c: &mut Criterion) {
    c.bench_function("setup/PublicParams", |b| {
        b.iter(|| black_box(PublicParams::setup()))
    });

    c.bench_function("setup/keypair_generation", |b| {
        let mut rng = OsRng;
        let pp = PublicParams::setup();
        b.iter(|| {
            let sk_c = ClientSecret::new(&mut rng);
            let sk_s = ServerSecret::new(&mut rng);
            let _ = black_box((sk_c.public(&pp), sk_s.public(&pp)));
        })
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Issuance protocol
// ─────────────────────────────────────────────────────────────────────────────

fn bench_issuance(c: &mut Criterion) {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let pk_s = sk_s.public(&pp);
    let expiry = now_secs() + 86400;

    c.bench_function("issuance/client_issue_query", |b| {
        b.iter(|| {
            black_box(client_issue_query(&mut OsRng, &pp, &sk_c, &pk_s, expiry))
        })
    });

    c.bench_function("issuance/server_issue_response", |b| {
        b.iter_batched(
            || {
                let (t, cp, _) = client_issue_query(&mut OsRng, &pp, &sk_c, &pk_s, expiry);
                (t, cp)
            },
            |(t, cp)| {
                black_box(
                    server_issue_response(&mut OsRng, &pp, &sk_s, &pk_c, &t, &cp, &pk_s, expiry).unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("issuance/client_finalize", |b| {
        b.iter_batched(
            || {
                let (t, cp, state) = client_issue_query(&mut OsRng, &pp, &sk_c, &pk_s, expiry);
                let (s, s_val, sp) =
                    server_issue_response(&mut OsRng, &pp, &sk_s, &pk_c, &t, &cp, &pk_s, expiry).unwrap();
                (state, s, s_val, sp)
            },
            |(state, s, s_val, sp)| {
                black_box(client_finalize(&pp, &pk_s, state, s, s_val, &sp, sk_c.x).unwrap())
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("issuance/full_round_trip", |b| {
        b.iter(|| black_box(issue_fresh_token(&mut OsRng, &pp, &sk_c, &sk_s)))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Rate-limiting generators
// ─────────────────────────────────────────────────────────────────────────────

fn bench_rate_limit_generators(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limit/generators");
    for n in [4usize, 16, 64, 128, 256] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| black_box(derive_rate_limit_generators(1, b"app", n)))
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Rate-limit proof (prove + verify)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_rate_limit_proof(c: &mut Criterion) {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let (token, witness) = issue_fresh_token(&mut rng, &pp, &sk_c, &sk_s);

    let mut group = c.benchmark_group("rate_limit/proof");
    for &n in &[16usize, 64, 128, 256] {
        let state = RateLimitState::new(1, b"app".to_vec(), n);
        let slot = n / 2;
        let com = RistrettoPoint::default();
        let r_com = Scalar::zero();

        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, _| {
            b.iter(|| {
                black_box(create_rate_limited_redemption(
                    &mut OsRng, &pp, &token, &witness, &state, slot, r_com, com,
                ))
            })
        });

        // Pre-generate a proof for verification benchmark
        let (proof, _) = create_rate_limited_redemption(&mut rng, &pp, &token, &witness, &state, slot, r_com, com);

        group.bench_with_input(BenchmarkId::new("verify", n), &n, |b, _| {
            b.iter(|| {
                black_box(verify_rate_limited_proof_only(&pp, &sk_s, &proof, &state))
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. File commitment
// ─────────────────────────────────────────────────────────────────────────────

fn bench_file_commitment(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);

    let mut group = c.benchmark_group("file_binding/commitment");
    for &kb in &[4usize, 16, 64, 256, 1024] {
        let mut data = vec![0u8; kb * 1024];
        rng.fill_bytes(&mut data);
        let file_id = [kb as u8; 32];

        group.bench_with_input(BenchmarkId::new("create", format!("{}KB", kb)), &kb, |b, _| {
            b.iter(|| {
                black_box(create_file_commitment_auto(&mut OsRng, file_id, &data, &sk_c.x))
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. File proof (create + verify)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_file_proof(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk_c = ClientSecret::new(&mut rng);
    let slot_gen = derive_rate_limit_generators(1, b"app", 2)[0];
    let tag = slot_gen * sk_c.x;
    let nonce = [0u8; 32];

    let mut group = c.benchmark_group("file_binding/proof");
    for &kb in &[4usize, 16, 64, 256] {
        let mut data = vec![0u8; kb * 1024];
        rng.fill_bytes(&mut data);
        let file_id = [kb as u8; 32];
        let (fc, ct, leaves) = create_file_commitment_auto(&mut rng, file_id, &data, &sk_c.x);
        let n = auto_challenge_count(fc.num_blocks, 0.99).min(fc.num_blocks as usize);

        group.bench_with_input(BenchmarkId::new("create", format!("{}KB", kb)), &kb, |b, _| {
            b.iter(|| {
                black_box(create_file_proof(
                    &mut OsRng, &sk_c.x, file_id, &ct, &leaves,
                    &fc.root_hash, &nonce, n, &slot_gen, &tag,
                ))
            })
        });

        let proof = create_file_proof(&mut rng, &sk_c.x, file_id, &ct, &leaves, &fc.root_hash, &nonce, n, &slot_gen, &tag);

        group.bench_with_input(BenchmarkId::new("verify", format!("{}KB", kb)), &kb, |b, _| {
            b.iter(|| {
                black_box(verify_file_proof(&proof, &fc, &nonce, &slot_gen, &tag))
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Bulletproof
// ─────────────────────────────────────────────────────────────────────────────

fn bench_bulletproof(c: &mut Criterion) {
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let e = now_secs() + 3600;
    let t_now = now_secs();
    let ctx = b"bench_ctx";

    c.bench_function("bulletproof/prove", |b| {
        b.iter(|| black_box(prove_greater_than(&bp_gens, &pc_gens, e, t_now, ctx)))
    });

    let (data, _, _) = prove_greater_than(&bp_gens, &pc_gens, e, t_now, ctx);
    c.bench_function("bulletproof/verify", |b| {
        b.iter(|| black_box(verify_bp(&bp_gens, &pc_gens, &data, ctx)))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Combined redemption (prove + verify)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_combined(c: &mut Criterion) {
    let mut rng = OsRng;
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let sk_s = ServerSecret::new(&mut rng);
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let ctx = b"bench_combined";
    let t_now = now_secs();

    let mut group = c.benchmark_group("combined");
    for &kb in &[4usize, 16, 64] {
        let (_token, _witness) = issue_fresh_token(&mut rng, &pp, &sk_c, &sk_s);
        let mut data = vec![0u8; kb * 1024];
        rng.fill_bytes(&mut data);
        let file_id = [kb as u8; 32];
        let (fc, ct, leaves) = create_file_commitment_auto(&mut rng, file_id, &data, &sk_c.x);
        let rate_state = RateLimitState::new(1, b"bench".to_vec(), 64);
        let slot = 32;
        let nonce = [0u8; 32];
        let n = auto_challenge_count(fc.num_blocks, 0.99).min(fc.num_blocks as usize);

        group.bench_with_input(BenchmarkId::new("prove", format!("{}KB", kb)), &kb, |b, _| {
            b.iter_batched(
                || issue_fresh_token(&mut OsRng, &pp, &sk_c, &sk_s),
                |(tok, wit)| {
                    black_box(create_combined_redemption(
                        &mut OsRng, &pp, &tok, &wit, &rate_state, slot,
                        file_id, &ct, &leaves, &fc.root_hash, nonce, n,
                        t_now, &bp_gens, &pc_gens, ctx,
                    ))
                },
                criterion::BatchSize::SmallInput,
            )
        });

        // Pre-generate proof for verify benchmark using a fresh rate_state so the tag isn't consumed
        let rate_state_v = RateLimitState::new(1, b"bench_v".to_vec(), 64);
        let (tok2, wit2) = issue_fresh_token(&mut rng, &pp, &sk_c, &sk_s);
        let proof = create_combined_redemption(
            &mut rng, &pp, &tok2, &wit2, &rate_state_v, slot,
            file_id, &ct, &leaves, &fc.root_hash, nonce, n,
            t_now, &bp_gens, &pc_gens, ctx,
        );

        group.bench_with_input(BenchmarkId::new("verify", format!("{}KB", kb)), &kb, |b, _| {
            // Each verify call will attempt to mark the same tag again and fail after first,
            // so we use verify_rate_limited_proof_only path is only in combined, but
            // we still get the timing of all verification logic up to the tag dedup.
            // For a clean timing we use a fresh rate_state per iteration.
            b.iter_batched(
                || {
                    let rs = RateLimitState::new(1, b"bench_iter".to_vec(), 64);
                    rs
                },
                |rs| {
                    // Note: this re-uses the same proof bytes; only the used_tags map is fresh.
                    black_box(verify_combined_redemption(
                        &pp, &sk_s, &proof, &rs, &fc, slot,
                        t_now, &bp_gens, &pc_gens, ctx,
                    ))
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Register all benchmark groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_setup,
    bench_issuance,
    bench_rate_limit_generators,
    bench_rate_limit_proof,
    bench_file_commitment,
    bench_file_proof,
    bench_bulletproof,
    bench_combined,
);
criterion_main!(benches);
