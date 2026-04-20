use curve25519_dalek_ng::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha512, Digest};

pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

pub fn hash_to_scalar(prefix: &[u8], data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(data);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
