use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};

use crate::base::{PublicParams, ServerSecret, Token, Witness};
use crate::rate_limit::{RateLimitState, RateLimitProof, verify_rate_limited_proof_only};
use crate::file_binding::{
    FileCommitment, FileProof, create_file_proof, verify_file_proof,
    auto_challenge_count, expected_challenge_count,
};
use crate::proof::{ProofData, prove_greater_than, verify as verify_bulletproof};

// -----------------------------------------------------------------------------
// Combined proof
// -----------------------------------------------------------------------------
#[derive(Clone, Serialize, Deserialize)]
pub struct CombinedRedemptionProof {
    pub rate_proof: RateLimitProof,
    pub file_proof: FileProof,
    pub bp_data: ProofData, // Range Proof
    pub challenge_nonce: [u8; 32],
}

pub fn create_combined_redemption<R: RngCore + CryptoRng>(
    rng: &mut R, pp: &PublicParams, token: &Token, witness: &Witness, rate_state: &RateLimitState, slot: usize,
    file_id: [u8; 32], ciphertexts: &[crate::file_binding::CiphertextBlock], leaves: &[[u8; 32]], file_root: &[u8; 32],
    challenge_nonce: [u8; 32], num_challenges: usize,
    time: u64, bp_gens: &BulletproofGens, pc_gens: &PedersenGens, context_id: &[u8],
) -> CombinedRedemptionProof {
    
    // 1. Generate Bulletproof logic 
    let (bp_data, _, r_com) = prove_greater_than(bp_gens, pc_gens, witness.e, time, context_id);
    let com_bp = bp_data.commitment.decompress().unwrap();
    let com = com_bp + pc_gens.B * Scalar::from(time);

    // 2. Wrap via Rate Limiting + Sigma Bridge
    let (rate_proof, tag) = crate::rate_limit::create_rate_limited_redemption(
        rng, pp, token, witness, rate_state, slot, r_com, com
    );
    let slot_generator = rate_state.generators[slot];
    
    // 3. Independent File Proof
    let file_proof = create_file_proof(
        rng, &witness.x, file_id, ciphertexts, leaves, file_root, &challenge_nonce, num_challenges, &slot_generator, &tag,
    );
    
    CombinedRedemptionProof { rate_proof, file_proof, bp_data, challenge_nonce }
}

pub fn verify_combined_redemption(
    pp: &PublicParams, sk_s: &ServerSecret, combined: &CombinedRedemptionProof, rate_state: &RateLimitState,
    file_commitment: &FileCommitment, slot: usize,
    time: u64, bp_gens: &BulletproofGens, pc_gens: &PedersenGens, context_id: &[u8],
) -> bool {
    // 1. Verify rate-limiting + Sigma Bridge (trusts `com` if true)
    if !verify_rate_limited_proof_only(pp, sk_s, &combined.rate_proof, rate_state) {
        return false;
    }

    // 2. Mathematically hand off `com` to the Bulletproof
    let com = combined.rate_proof.com;
    let expected_com_bp = com - pc_gens.B * Scalar::from(time);
    if expected_com_bp.compress() != combined.bp_data.commitment {
        return false;
    }

    // 3. Verify Bulletproof (Enforces e > time)
    if !verify_bulletproof(bp_gens, pc_gens, &combined.bp_data, context_id) {
        return false;
    }

    // 4. Verify file proof
    let slot_generator = rate_state.generators[slot];
    if !verify_file_proof(&combined.file_proof, file_commitment, &combined.challenge_nonce, &slot_generator, &combined.rate_proof.tag) {
        return false;
    }
    
    // 5. Atomically mark the tag as used
    let key = combined.rate_proof.tag.compress().to_bytes();
    let mut guard = rate_state.used_tags.lock().unwrap();
    if guard.contains(&key) { false } else { guard.insert(key); true }
}

pub fn create_combined_redemption_auto<R: RngCore + CryptoRng>(
    rng: &mut R, pp: &PublicParams, token: &Token, witness: &Witness, rate_state: &RateLimitState, slot: usize,
    file_id: [u8; 32], ciphertexts: &[crate::file_binding::CiphertextBlock], leaves: &[[u8; 32]], file_root: &[u8; 32],
    challenge_nonce: [u8; 32], confidence: f64,
    time: u64, bp_gens: &BulletproofGens, pc_gens: &PedersenGens, context_id: &[u8],
) -> CombinedRedemptionProof {
    let num_challenges = auto_challenge_count(ciphertexts.len() as u64, confidence);
    create_combined_redemption(
        rng, pp, token, witness, rate_state, slot, file_id, ciphertexts, leaves, file_root, challenge_nonce, num_challenges,
        time, bp_gens, pc_gens, context_id
    )
}

pub fn verify_combined_redemption_auto(
    pp: &PublicParams, sk_s: &ServerSecret, combined: &CombinedRedemptionProof, rate_state: &RateLimitState,
    file_commitment: &FileCommitment, slot: usize, confidence: f64,
    time: u64, bp_gens: &BulletproofGens, pc_gens: &PedersenGens, context_id: &[u8],
) -> bool {
    let expected = expected_challenge_count(file_commitment, confidence);
    if combined.file_proof.blocks.len() != expected { return false; }
    verify_combined_redemption(pp, sk_s, combined, rate_state, file_commitment, slot, time, bp_gens, pc_gens, context_id)
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{ClientSecret, ServerSecret, PublicParams, client_issue_query, server_issue_response, client_finalize};
    use crate::rate_limit::{RateLimitState, RateLimitProof};
    use crate::file_binding::{create_file_commitment_auto, auto_challenge_count, FileProof};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use rand::rngs::OsRng;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

 #[test]
    fn detailed_combined_redemption() {
        use rand_core::RngCore; // Needed for fill_bytes
        let mut rng = OsRng;
        
        println!("\n=== 🚀 COMPREHENSIVE NTAT + BULLETPROOFS BENCHMARK (50 KB FILE) 🚀 ===");
        
        // 1. Setup Generators & Keys
        let start = Instant::now();
        let pp = PublicParams::setup();
        let sk_c = ClientSecret::new(&mut rng);
        let pk_c = sk_c.public(&pp);
        let sk_s = ServerSecret::new(&mut rng);
        let pk_s = sk_s.public(&pp);
        
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();
        println!("Setup time: {:?}", start.elapsed());

        // 2. Time Logic
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let valid_expiry = current_time + 86400; // 24 hours in the future
        println!("Current Time: {}, Token Expiry: {}", current_time, valid_expiry);

        // 3. Issuance
        let start = Instant::now();
        let (t, proof_c, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, valid_expiry);
        let (s, s_val, proof_s) = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &proof_c, &pk_s, valid_expiry).unwrap();
        let (token, witness) = client_finalize(&pp, &pk_s, state, s, s_val, &proof_s, sk_c.x).unwrap();
        println!("Issuance time: {:?}", start.elapsed());

        // 4. File Commitment (NOW 50 KB)
        println!("\n--- Generating 50 KB File ---");
        let mut file_data = vec![0u8; 5 * 1024]; // 50 KB of data
        rng.fill_bytes(&mut file_data);           // Fill with random bytes to simulate real entropy
        
        let file_id = [99u8; 32];
        let start = Instant::now();
        let (file_commitment, ciphertexts, leaves) = create_file_commitment_auto(&mut rng, file_id, &file_data, &sk_c.x);
        println!("File commitment time: {:?}", start.elapsed());
        println!("File blocks: {}, block size: {} bytes", file_commitment.num_blocks, file_commitment.block_size);

        // 5. Rate Limit State
        let app_id = b"secure_banking_app".to_vec();
        let rate_state = RateLimitState::new(42, app_id, 128); // Epoch 42, 128 slots
        let slot = 15; // Client decides to use slot 15
        
        let challenge_nonce = [7u8; 32];
        let confidence = 0.95;
        let num_challenges = auto_challenge_count(file_commitment.num_blocks, confidence);
        println!("File Proof Challenges Required (95% confidence): {}", num_challenges);

        // 6. Combined Proof Creation (Client Side)
        let context_id = b"tx_987654321_alice";
        let start = Instant::now();
        let combined = create_combined_redemption(
            &mut rng, &pp, &token, &witness, &rate_state, slot,
            file_id, &ciphertexts, &leaves, &file_commitment.root_hash,
            challenge_nonce, num_challenges,
            current_time, &bp_gens, &pc_gens, context_id
        );
        println!("Combined proof creation time: {:?}", start.elapsed());
        
        // Print Sizes
        println!("\n--- Proof Sizes ---");
        println!("Total Combined Proof : {} bytes", bincode::serialize(&combined).unwrap().len());
        println!("  ├─ Rate Limit Proof: {} bytes", bincode::serialize(&combined.rate_proof).unwrap().len());
        println!("  ├─ File Proof      : {} bytes", bincode::serialize(&combined.file_proof).unwrap().len());
        println!("  └─ Range Proof     : {} bytes", combined.bp_data.proof.to_bytes().len());

        // 7. Combined Proof Verification (Server Side)
        let start = Instant::now();
        let valid = verify_combined_redemption(
            &pp, &sk_s, &combined, &rate_state, &file_commitment, slot,
            current_time, &bp_gens, &pc_gens, context_id
        );
        println!("\nVerification time: {:?}", start.elapsed());
        assert!(valid, "The comprehensive combined proof failed to verify!");
        println!("✅ Combined redemption mathematically verified.");

        // 8. Double Spend Prevention
        let is_valid_replay = verify_combined_redemption(
            &pp, &sk_s, &combined, &rate_state, &file_commitment, slot,
            current_time, &bp_gens, &pc_gens, context_id
        );
        assert!(!is_valid_replay, "Double spend was not prevented!");
        println!("🔒 Double spend properly caught and blocked.\n");
    }
    #[test]
    fn test_expired_token_fails() {
        let mut rng = OsRng;
        let pp = PublicParams::setup();
        let sk_s = ServerSecret::new(&mut rng);
        let pk_s = sk_s.public(&pp);
        let sk_c = ClientSecret::new(&mut rng);
        let pk_c = sk_c.public(&pp);

        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();
        
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expired_time = current_time - 3600; // 1 hour in the past

        // ISSUANCE WITH EXPIRED TIME
        let (t, client_proof, state) = client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expired_time);
        let (s, s_val, server_proof) = server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &t, &client_proof, &pk_s, expired_time).unwrap();
        let (token, witness) = client_finalize(&pp, &pk_s, state, s, s_val, &server_proof, sk_c.x).unwrap();

        let rate_state = RateLimitState::new(1, b"app".to_vec(), 10);
        let (file_comm, ciphertexts, leaves) = crate::file_binding::create_file_commitment(&mut rng, [0; 32], &[b"data".to_vec()], &witness.x);

        // Catch the panic that Bulletproofs throws when attempting to prove a negative number (e < time)
        let result = std::panic::catch_unwind(|| {
            let mut rng_clone = OsRng;
            create_combined_redemption(
                &mut rng_clone, &pp, &token, &witness, &rate_state, 0,
                [0; 32], &ciphertexts, &leaves, &file_comm.root_hash,
                [0; 32], 1, current_time, &bp_gens, &pc_gens, b"ctx"
            )
        });
        
        assert!(result.is_err(), "Client should mathematically fail to generate a range proof for an expired token.");
    }
}
