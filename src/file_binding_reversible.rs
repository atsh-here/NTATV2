use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{CryptoRng, RngCore};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};
use rayon::prelude::*;

use crate::utils::random_scalar;
use crate::serde_utils::ristretto_serde;

pub const BATCH_THRESHOLD: usize = 3;

fn merkle_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"MERKLE_LEAF");
    hasher.update(leaf);
    hasher.finalize()[..32].try_into().unwrap()
}

fn merkle_combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"MERKLE_NODE");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()[..32].try_into().unwrap()
}

fn build_merkle_tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() { return vec![vec![[0u8; 32]]]; }
    let mut tree = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_hash(l)).collect();
    tree.push(level.clone());
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 { next.push(merkle_combine(&chunk[0], &chunk[1])); } else { next.push(chunk[0]); }
        }
        tree.push(next.clone()); level = next;
    }
    tree
}

pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<(bool, [u8; 32])> {
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_hash(l)).collect();
    let mut idx = index;
    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() { path.push((sibling_idx < idx, level[sibling_idx])); }
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 { next.push(merkle_combine(&chunk[0], &chunk[1])); } else { next.push(chunk[0]); }
        }
        idx /= 2; level = next;
    }
    path
}

fn verify_merkle_path(leaf: &[u8; 32], _index: usize, path: &[(bool, [u8; 32])], root: &[u8; 32]) -> bool {
    let mut current = merkle_hash(leaf);
    for (is_left, sibling) in path {
        if *is_left { current = merkle_combine(sibling, &current); } else { current = merkle_combine(&current, sibling); }
    }
    &current == root
}

/// We encode file bytes directly into compressed Ristretto encodings.
///
/// A curve point cannot carry an arbitrary large block. This encoding stores
/// up to 28 bytes of payload in the first 28 bytes of the compressed point and
/// searches over a 32-bit counter in the last 4 bytes until the 32-byte string
/// is a valid canonical compressed Ristretto point.
///
/// This is reversible:
///   payload -> compressed bytes -> RistrettoPoint -> compressed bytes -> payload
///
/// The only failure mode is exhausting all 2^32 counters for a payload. The
/// expected number of tries is small because a substantial fraction of 32-byte
/// strings decompress to valid Ristretto points. We still return Result instead
/// of silently falling back to a one-way hash.
pub const REVERSIBLE_POINT_ENCODING_V1: u32 = 1;
pub const REVERSIBLE_POINT_PAYLOAD_SIZE: usize = 28;
pub const REVERSIBLE_POINT_COUNTER_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointEncodingError {
    ChunkTooLarge { len: usize, max: usize },
    NoValidEncoding,
    InvalidDecodedLength { len: usize, max: usize },
}

pub fn encode_chunk_to_point(chunk: &[u8]) -> Result<RistrettoPoint, PointEncodingError> {
    if chunk.len() > REVERSIBLE_POINT_PAYLOAD_SIZE {
        return Err(PointEncodingError::ChunkTooLarge { len: chunk.len(), max: REVERSIBLE_POINT_PAYLOAD_SIZE });
    }

    let mut payload = [0u8; REVERSIBLE_POINT_PAYLOAD_SIZE];
    payload[..chunk.len()].copy_from_slice(chunk);

    let mut counter = 0u32;
    loop {
        let mut candidate = [0u8; 32];
        candidate[..REVERSIBLE_POINT_PAYLOAD_SIZE].copy_from_slice(&payload);
        candidate[REVERSIBLE_POINT_PAYLOAD_SIZE..]
            .copy_from_slice(&counter.to_le_bytes());

        if let Some(point) = CompressedRistretto(candidate).decompress() {
            // Canonical round-trip check. This prevents accepting a point whose
            // canonical encoding is not exactly the bytes carrying our payload.
            if point.compress().to_bytes() == candidate {
                return Ok(point);
            }
        }

        if counter == u32::MAX { break; }
        counter = counter.wrapping_add(1);
    }

    Err(PointEncodingError::NoValidEncoding)
}

pub fn decode_point_to_chunk(point: &RistrettoPoint, chunk_len: usize) -> Result<Vec<u8>, PointEncodingError> {
    if chunk_len > REVERSIBLE_POINT_PAYLOAD_SIZE {
        return Err(PointEncodingError::InvalidDecodedLength { len: chunk_len, max: REVERSIBLE_POINT_PAYLOAD_SIZE });
    }
    let bytes = point.compress().to_bytes();
    Ok(bytes[..chunk_len].to_vec())
}

fn elgamal_encrypt_block<R: RngCore + CryptoRng>(rng: &mut R, m: &RistrettoPoint, pk: &RistrettoPoint) -> (RistrettoPoint, RistrettoPoint) {
    let r = random_scalar(rng);
    let c1 = r * RISTRETTO_BASEPOINT_POINT;
    let c2 = *m + r * pk;
    (c1, c2)
}

fn elgamal_decrypt_block(x: &Scalar, c1: &RistrettoPoint, c2: &RistrettoPoint) -> RistrettoPoint { *c2 - x * c1 }

#[derive(Clone, Serialize, Deserialize)]
pub struct DLEQProof {
    #[serde(with = "ristretto_serde")] pub t1: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub t2: RistrettoPoint,
    pub s: Scalar,
}

impl DLEQProof {
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, x: &Scalar, a: &RistrettoPoint, b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint) -> Self {
        let r = random_scalar(rng);
        let t1 = r * a; let t2 = r * c;
        let mut hasher = Sha512::new();
        hasher.update(b"DLEQ_PROOF");
        hasher.update(a.compress().as_bytes()); hasher.update(b.compress().as_bytes());
        hasher.update(c.compress().as_bytes()); hasher.update(d.compress().as_bytes());
        hasher.update(t1.compress().as_bytes()); hasher.update(t2.compress().as_bytes());
        let challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let s = r + challenge * x;
        DLEQProof { t1, t2, s }
    }

    pub fn verify(&self, a: &RistrettoPoint, b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(b"DLEQ_PROOF");
        hasher.update(a.compress().as_bytes()); hasher.update(b.compress().as_bytes());
        hasher.update(c.compress().as_bytes()); hasher.update(d.compress().as_bytes());
        hasher.update(self.t1.compress().as_bytes()); hasher.update(self.t2.compress().as_bytes());
        let challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let left1 = self.s * a - challenge * b; let left2 = self.s * c - challenge * d;
        left1 == self.t1 && left2 == self.t2
    }
}

pub type BatchDLEQProof = DLEQProof;

fn derive_batch_coefficients(pairs: &[(RistrettoPoint, RistrettoPoint)]) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(pairs.len());
    for i in 0..pairs.len() {
        let mut hasher = Sha512::new();
        hasher.update(b"NTAT:BATCH:DLEQ");
        for (a, b) in pairs.iter() {
            let a_pt: &RistrettoPoint = a; // Fix for E0282
            let b_pt: &RistrettoPoint = b;
            hasher.update(a_pt.compress().as_bytes());
            hasher.update(b_pt.compress().as_bytes());
        }
        hasher.update(&(i as u64).to_le_bytes());
        coeffs.push(Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()));
    }
    coeffs
}

fn combine_pairs(pairs: &[(RistrettoPoint, RistrettoPoint)], coeffs: &[Scalar]) -> (RistrettoPoint, RistrettoPoint) {
    let mut a_sum = RistrettoPoint::default(); let mut b_sum = RistrettoPoint::default();
    for ((a, b), rho) in pairs.iter().zip(coeffs) { a_sum += rho * a; b_sum += rho * b; }
    (a_sum, b_sum)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileCommitment {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub num_blocks: u64,
    /// Maximum plaintext bytes encoded into one Ristretto point.
    pub block_size: usize,
    /// Exact original file size in bytes. Needed to decode the final padded point.
    pub file_size: u64,
    /// Encoding version for reversible point encoding.
    pub encoding_version: u32,
    pub nonce: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CiphertextBlock {
    #[serde(with = "ristretto_serde")] pub c1: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub c2: RistrettoPoint,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockProof {
    pub index: u64, pub ciphertext: CiphertextBlock,
    #[serde(with = "ristretto_serde")] pub decrypted_point: RistrettoPoint,
    pub merkle_path: Vec<(bool, [u8; 32])>, pub dleq_proof: Option<DLEQProof>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileProof {
    pub file_id: [u8; 32], pub root_hash: [u8; 32], pub blocks: Vec<BlockProof>, pub batch_proof: Option<BatchDLEQProof>,
}

fn prepare_file_blocks<R: RngCore + CryptoRng>(_rng: &mut R, pre_encrypted_blocks: &[Vec<u8>], x: &Scalar, _nonce: &[u8; 32]) -> (Vec<CiphertextBlock>, Vec<[u8; 32]>, [u8; 32]) {
    let pk = x * RISTRETTO_BASEPOINT_POINT;
    let (ciphertexts, leaves): (Vec<_>, Vec<_>) = pre_encrypted_blocks.par_iter().map(|block_bytes| {
        let mut thread_rng = rand::thread_rng();
        let m = encode_chunk_to_point(block_bytes)
            .expect("reversible point encoding failed; use smaller chunks or check encoding parameters");
        let (c1, c2) = elgamal_encrypt_block(&mut thread_rng, &m, &pk);
        let mut hasher = Sha512::new();
        hasher.update(b"CIPHER_LEAF"); hasher.update(c1.compress().as_bytes()); hasher.update(c2.compress().as_bytes());
        let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
        (CiphertextBlock { c1, c2 }, leaf)
    }).unzip();
    let tree = build_merkle_tree(&leaves);
    let root = *tree.last().unwrap().first().unwrap();
    (ciphertexts, leaves, root)
}

pub fn create_file_commitment<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], pre_encrypted_blocks: &[Vec<u8>], x: &Scalar) -> (FileCommitment, Vec<CiphertextBlock>, Vec<[u8; 32]>) {
    for block in pre_encrypted_blocks {
        assert!(block.len() <= REVERSIBLE_POINT_PAYLOAD_SIZE, "block too large for reversible Ristretto encoding");
    }
    let nonce = random_scalar(rng).to_bytes();
    let file_size: u64 = pre_encrypted_blocks.iter().map(|b| b.len() as u64).sum();
    let (ciphertexts, leaves, root) = prepare_file_blocks(rng, pre_encrypted_blocks, x, &nonce);
    let commitment = FileCommitment {
        file_id,
        root_hash: root,
        num_blocks: pre_encrypted_blocks.len() as u64,
        block_size: REVERSIBLE_POINT_PAYLOAD_SIZE,
        file_size,
        encoding_version: REVERSIBLE_POINT_ENCODING_V1,
        nonce,
    };
    (commitment, ciphertexts, leaves)
}

fn derive_challenge_indices(nonce: &[u8; 32], num_blocks: u64, num_challenges: usize) -> Vec<u64> {
    let mut hasher = Sha512::new(); hasher.update(b"CHALLENGE_INDICES"); hasher.update(nonce);
    let seed = hasher.finalize();
    let mut rng = StdRng::from_seed(seed[..32].try_into().unwrap());
    let mut indices: Vec<u64> = (0..num_blocks).collect();
    indices.shuffle(&mut rng); indices.truncate(num_challenges); indices.sort(); indices
}

pub fn create_file_proof<R: RngCore + CryptoRng>(
    rng: &mut R, x: &Scalar, file_id: [u8; 32], ciphertexts: &[CiphertextBlock], leaves: &[[u8; 32]],
    root_hash: &[u8; 32], challenge_nonce: &[u8; 32], num_challenges: usize, slot_generator: &RistrettoPoint, tag: &RistrettoPoint,
) -> FileProof {
    let num_blocks = ciphertexts.len() as u64;
    let indices = derive_challenge_indices(challenge_nonce, num_blocks, num_challenges);
    let use_batch = num_challenges >= BATCH_THRESHOLD;
    let mut blocks = Vec::new();
    let mut pairs = if use_batch { Some(Vec::with_capacity(1 + num_challenges)) } else { None };
    if use_batch { pairs.as_mut().unwrap().push((*slot_generator, *tag)); }

    for idx in indices {
        let i = idx as usize; let cipher = &ciphertexts[i];
        let m = elgamal_decrypt_block(x, &cipher.c1, &cipher.c2); let d = cipher.c2 - m;
        let path = merkle_path(leaves, i);
        let dleq_proof = if use_batch { pairs.as_mut().unwrap().push((cipher.c1, d)); None } else {
            Some(DLEQProof::prove(rng, x, slot_generator, tag, &cipher.c1, &d))
        };
        blocks.push(BlockProof { index: idx, ciphertext: cipher.clone(), decrypted_point: m, merkle_path: path, dleq_proof });
    }

    let batch_proof = if use_batch {
        let pairs = pairs.unwrap(); let coeffs = derive_batch_coefficients(&pairs);
        let (a, b) = combine_pairs(&pairs, &coeffs);
        Some(DLEQProof::prove(rng, x, slot_generator, tag, &a, &b))
    } else { None };

    FileProof { file_id, root_hash: *root_hash, blocks, batch_proof }
}

pub fn verify_file_proof(proof: &FileProof, stored_commitment: &FileCommitment, challenge_nonce: &[u8; 32], slot_generator: &RistrettoPoint, tag: &RistrettoPoint) -> bool {
    if proof.file_id != stored_commitment.file_id || proof.root_hash != stored_commitment.root_hash { return false; }
    let num_blocks = stored_commitment.num_blocks;
    let expected_indices = derive_challenge_indices(challenge_nonce, num_blocks, proof.blocks.len());
    let use_batch = proof.batch_proof.is_some();

    if use_batch {
        let mut pairs = Vec::with_capacity(1 + proof.blocks.len()); pairs.push((*slot_generator, *tag));
        for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
            if block.index != expected_idx || block.dleq_proof.is_some() { return false; }
            let mut hasher = Sha512::new(); hasher.update(b"CIPHER_LEAF");
            hasher.update(block.ciphertext.c1.compress().as_bytes()); hasher.update(block.ciphertext.c2.compress().as_bytes());
            let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
            if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
            let d = block.ciphertext.c2 - block.decrypted_point; pairs.push((block.ciphertext.c1, d));
        }
        let coeffs = derive_batch_coefficients(&pairs); let (a, b) = combine_pairs(&pairs, &coeffs);
        proof.batch_proof.as_ref().unwrap().verify(slot_generator, tag, &a, &b)
    } else {
        for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
            if block.index != expected_idx || block.dleq_proof.is_none() { return false; }
            let mut hasher = Sha512::new(); hasher.update(b"CIPHER_LEAF");
            hasher.update(block.ciphertext.c1.compress().as_bytes()); hasher.update(block.ciphertext.c2.compress().as_bytes());
            let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
            if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
            let d = block.ciphertext.c2 - block.decrypted_point;
            if !block.dleq_proof.as_ref().unwrap().verify(slot_generator, tag, &block.ciphertext.c1, &d) { return false; }
        }
        true
    }
}

pub fn auto_block_size(_file_size_bytes: usize) -> usize {
    // Direct EC-ElGamal encrypts one group element per block. With reversible
    // compressed-Ristretto encoding, one point carries 28 plaintext bytes.
    REVERSIBLE_POINT_PAYLOAD_SIZE
}

pub fn auto_challenge_count(num_blocks: u64, confidence: f64) -> usize {
    if num_blocks == 0 { return 0; }
    if num_blocks == 1 { return 1; }
    let p_miss_single = 1.0 - 1.0 / (num_blocks as f64);
    let required = ((1.0 - confidence).ln() / p_miss_single.ln()).ceil();
    (required as usize).clamp(10, 100)
}

pub fn create_file_commitment_auto<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], file_data: &[u8], x: &Scalar) -> (FileCommitment, Vec<CiphertextBlock>, Vec<[u8; 32]>) {
    let block_size = auto_block_size(file_data.len());
    let blocks: Vec<Vec<u8>> = file_data.chunks(block_size).map(|chunk| chunk.to_vec()).collect();
    create_file_commitment(rng, file_id, &blocks, x)
}

pub fn decrypt_file_from_ciphertexts(ciphertexts: &[CiphertextBlock], commitment: &FileCommitment, x: &Scalar) -> Result<Vec<u8>, PointEncodingError> {
    assert_eq!(ciphertexts.len() as u64, commitment.num_blocks, "ciphertext count does not match commitment");
    assert_eq!(commitment.encoding_version, REVERSIBLE_POINT_ENCODING_V1, "unsupported file encoding version");

    let mut out = Vec::with_capacity(commitment.file_size as usize);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        let m = elgamal_decrypt_block(x, &cipher.c1, &cipher.c2);
        let remaining = commitment.file_size as usize - out.len();
        let chunk_len = remaining.min(commitment.block_size);
        let chunk = decode_point_to_chunk(&m, chunk_len)?;
        out.extend_from_slice(&chunk);
        if i + 1 == ciphertexts.len() { break; }
    }
    Ok(out)
}

pub fn expected_challenge_count(commitment: &FileCommitment, confidence: f64) -> usize {
    auto_challenge_count(commitment.num_blocks, confidence)
}


#[cfg(test)]
mod file_binding_reversible_tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand_core::RngCore;

    #[test]
    fn reversible_point_encoding_roundtrip_all_lengths() {
        let mut rng = OsRng;
        for len in 0..=REVERSIBLE_POINT_PAYLOAD_SIZE {
            for _ in 0..16 {
                let mut chunk = vec![0u8; len];
                rng.fill_bytes(&mut chunk);
                let point = encode_chunk_to_point(&chunk).expect("chunk should encode");
                let decoded = decode_point_to_chunk(&point, len).expect("point should decode");
                assert_eq!(decoded, chunk);
            }
        }
    }

    #[test]
    fn elgamal_file_roundtrip_recovers_original_bytes() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let mut file = vec![0u8; 4097];
        rng.fill_bytes(&mut file);

        let (commitment, ciphertexts, _leaves) = create_file_commitment_auto(&mut rng, [7u8; 32], &file, &x);
        assert_eq!(commitment.block_size, REVERSIBLE_POINT_PAYLOAD_SIZE);
        assert_eq!(commitment.file_size, file.len() as u64);

        let recovered = decrypt_file_from_ciphertexts(&ciphertexts, &commitment, &x).expect("file should decrypt and decode");
        assert_eq!(recovered, file);
    }

    #[test]
    fn dleq_same_x_proof_still_verifies_with_reversible_blocks() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let mut file = vec![0u8; 1024];
        rng.fill_bytes(&mut file);

        let (commitment, ciphertexts, leaves) = create_file_commitment_auto(&mut rng, [9u8; 32], &file, &x);
        let slot_hash = Sha512::digest(b"test slot generator");
        let slot_generator = RistrettoPoint::from_uniform_bytes(&slot_hash.into());
        let tag = slot_generator * x;
        let challenge_nonce = [3u8; 32];
        let num_challenges = 10;

        let proof = create_file_proof(
            &mut rng,
            &x,
            commitment.file_id,
            &ciphertexts,
            &leaves,
            &commitment.root_hash,
            &challenge_nonce,
            num_challenges,
            &slot_generator,
            &tag,
        );

        assert!(verify_file_proof(&proof, &commitment, &challenge_nonce, &slot_generator, &tag));
    }
}
