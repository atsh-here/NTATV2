use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub proof: RangeProof,
    pub commitment: CompressedRistretto,
}

pub fn prove_greater_than(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    e: u64, 
    time: u64,
    context_id: &[u8]
) -> (ProofData, usize, Scalar) {
    assert!(e > time, "Expiration must be strictly greater than current time");
    let v = e - time;

    let mut transcript = Transcript::new(b"MySecureApp_Expiration_Proof");
    transcript.append_message(b"context_id", context_id);

    let mut rng = OsRng;
    let blinding = Scalar::random(&mut rng);

    let (proof, commitment) = RangeProof::prove_single(
        bp_gens,
        pc_gens,
        &mut transcript,
        v,
        &blinding,
        32
        ,
    ).expect("Failed to generate range proof");

    let size = proof.to_bytes().len();
    (ProofData { proof, commitment }, size, blinding)
}

pub fn verify(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    data: &ProofData,
    context_id: &[u8]
) -> bool {
    let mut transcript = Transcript::new(b"MySecureApp_Expiration_Proof");
    transcript.append_message(b"context_id", context_id);

    data.proof.verify_single(
        bp_gens,
        pc_gens,
        &mut transcript,
        &data.commitment,
        32,
    ).is_ok()
}
