use bulletproofs::{BulletproofGens, PedersenGens};
use rand::rngs::OsRng;
use rand_core::RngCore;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ntat::base::{
    client_finalize, client_issue_query, server_issue_response, ClientSecret, PublicParams,
    ServerSecret,
};
use ntat::combined::{create_combined_redemption, verify_combined_redemption};
use ntat::file_binding::{auto_challenge_count, create_file_commitment_auto};
use ntat::rate_limit::RateLimitState;

// Formatting helper for byte sizes
fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn main() {
    println!("\n==========================================================");
    println!("🚀 NTAT RIGOROUS END-TO-END PROFILER & BENCHMARK 🚀");
    println!("==========================================================\n");

    let mut rng = OsRng;

    // -------------------------------------------------------------------------
    // 1. SYSTEM SETUP
    // -------------------------------------------------------------------------
    println!("--- 1. SYSTEM SETUP ---");
    let t_setup = Instant::now();
    let pp = PublicParams::setup();
    let sk_c = ClientSecret::new(&mut rng);
    let pk_c = sk_c.public(&pp);
    let sk_s = ServerSecret::new(&mut rng);
    let pk_s = sk_s.public(&pp);

    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let d_setup = t_setup.elapsed();
    println!("✅ Generators & Keys initialized in {:?}", d_setup);

    // -------------------------------------------------------------------------
    // 2. ISSUANCE PROTOCOL
    // -------------------------------------------------------------------------
    println!("\n--- 2. ISSUANCE PROTOCOL (BLIND SIGNING) ---");
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = current_time + (30 * 24 * 60 * 60); // 30 days

    let t_issue_client = Instant::now();
    let (query, client_proof, issue_state) =
        client_issue_query(&mut rng, &pp, &sk_c, &pk_s, expiry);
    let d_issue_client = t_issue_client.elapsed();

    let t_issue_server = Instant::now();
    let (s, s_val, server_proof) =
        server_issue_response(&mut rng, &pp, &sk_s, &pk_c, &query, &client_proof, &pk_s, expiry)
            .expect("Server issuance failed");
    let d_issue_server = t_issue_server.elapsed();

    let t_finalize = Instant::now();
    let (token, witness) =
        client_finalize(&pp, &pk_s, issue_state, s, s_val, &server_proof, sk_c.x)
            .expect("Client finalize failed");
    let d_finalize = t_finalize.elapsed();

    println!("⏱️  Client Query Gen : {:?}", d_issue_client);
    println!("⏱️  Server Response  : {:?}", d_issue_server);
    println!("⏱️  Client Finalize  : {:?}", d_finalize);
    println!("📦 Client Proof Size: {}", format_size(bincode::serialize(&client_proof).unwrap().len()));
    println!("📦 Server Proof Size: {}", format_size(bincode::serialize(&server_proof).unwrap().len()));
    println!("📦 Token Size       : {}", format_size(bincode::serialize(&token).unwrap().len()));

    // -------------------------------------------------------------------------
    // 3. FILE BINDING (HEAVY WORKLOAD)
    // -------------------------------------------------------------------------
    let file_size_bytes = 1024 * 1024; // 1 MB file for rigorous testing
    println!("\n--- 3. FILE BINDING COMMITMENT ({} FILE) ---", format_size(file_size_bytes));
    
    let mut file_data = vec![0u8; file_size_bytes];
    rng.fill_bytes(&mut file_data);
    let file_id = [42u8; 32];

    let t_file_comm = Instant::now();
    let (file_commitment, ciphertexts, leaves) =
        create_file_commitment_auto(&mut rng, file_id, &file_data, &sk_c.x);
    let d_file_comm = t_file_comm.elapsed();

    println!("⏱️  Commitment Gen   : {:?}", d_file_comm);
    println!("📊 Total Blocks     : {}", file_commitment.num_blocks);
    println!("📊 Block Size       : {} bytes", file_commitment.block_size);
    println!("📦 Commitment Size  : {}", format_size(bincode::serialize(&file_commitment).unwrap().len()));
    println!("📦 Ciphertexts Size : {}", format_size(bincode::serialize(&ciphertexts).unwrap().len()));

    // -------------------------------------------------------------------------
    // 4. RATE LIMITING SETUP
    // -------------------------------------------------------------------------
    println!("\n--- 4. RATE LIMITING SETUP ---");
    let t_rate_setup = Instant::now();
    let app_id = b"global_storage_network".to_vec();
    let rate_state = RateLimitState::new(1001, app_id, 256); // 256 slots
    let slot = 128;
    let d_rate_setup = t_rate_setup.elapsed();
    println!("⏱️  State Gen (256)  : {:?}", d_rate_setup);

    // -------------------------------------------------------------------------
    // 5. COMBINED REDEMPTION PROOF GENERATION
    // -------------------------------------------------------------------------
    println!("\n--- 5. COMBINED PROOF GENERATION (CLIENT) ---");
    let challenge_nonce = [99u8; 32];
    let confidence = 0.99; // 99% confidence for rigorous checking
    let num_challenges = auto_challenge_count(file_commitment.num_blocks, confidence);
    let context_id = b"audit_trail_001";

    println!("🎯 File Challenges Required (99% confidence): {}", num_challenges);

    let t_prove = Instant::now();
    let combined_proof = create_combined_redemption(
        &mut rng, &pp, &token, &witness, &rate_state, slot,
        file_id, &ciphertexts, &leaves, &file_commitment.root_hash,
        challenge_nonce, num_challenges,
        current_time, &bp_gens, &pc_gens, context_id,
    );
    let d_prove = t_prove.elapsed();
    println!("⏱️  Proof Generation : {:?}", d_prove);

    // -------------------------------------------------------------------------
    // 6. PAYLOAD SIZE ANALYSIS
    // -------------------------------------------------------------------------
    println!("\n--- 6. PAYLOAD SIZE ANALYSIS ---");
    let size_rate = bincode::serialize(&combined_proof.rate_proof).unwrap().len();
    let size_file = bincode::serialize(&combined_proof.file_proof).unwrap().len();
    let size_bp = bincode::serialize(&combined_proof.bp_data).unwrap().len();
    let size_total = bincode::serialize(&combined_proof).unwrap().len();

    println!("📦 Rate Limit Proof : {}", format_size(size_rate));
    println!("📦 File Proof       : {}", format_size(size_file));
    println!("📦 Range Proof (BP) : {}", format_size(size_bp));
    println!("📦 Total Payload    : {}", format_size(size_total));

    // -------------------------------------------------------------------------
    // 7. VERIFICATION PROTOCOL
    // -------------------------------------------------------------------------
    println!("\n--- 7. COMBINED PROOF VERIFICATION (SERVER) ---");
    let t_verify = Instant::now();
    let is_valid = verify_combined_redemption(
        &pp, &sk_s, &combined_proof, &rate_state, &file_commitment, slot,
        current_time, &bp_gens, &pc_gens, context_id,
    );
    let d_verify = t_verify.elapsed();
    
    if is_valid {
        println!("✅ Verification Status: SUCCESS");
    } else {
        println!("❌ Verification Status: FAILED");
    }
    println!("⏱️  Verification Time: {:?}", d_verify);

    // -------------------------------------------------------------------------
    // 8. DOUBLE SPEND & REPLAY PROTECTION CHECK
    // -------------------------------------------------------------------------
    println!("\n--- 8. SECURITY ASSERTIONS ---");
    let t_replay = Instant::now();
    let is_replay_valid = verify_combined_redemption(
        &pp, &sk_s, &combined_proof, &rate_state, &file_commitment, slot,
        current_time, &bp_gens, &pc_gens, context_id,
    );
    let d_replay = t_replay.elapsed();
    
    if !is_replay_valid {
        println!("🔒 Double Spend Check: CAUGHT & BLOCKED (Tested in {:?})", d_replay);
    } else {
        println!("⚠️ Double Spend Check: FAILED TO BLOCK");
    }

    println!("\n==========================================================");
    println!("🏁 BENCHMARK COMPLETE");
    println!("==========================================================\n");
}
