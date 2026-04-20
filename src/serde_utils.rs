use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use serde::{Serializer, Deserializer, de};

pub mod ristretto_serde {
    use super::*;
    pub fn serialize<S>(p: &RistrettoPoint, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(p.compress().as_bytes())
    }
    pub fn deserialize<'de, D>(d: D) -> Result<RistrettoPoint, D::Error>
    where D: Deserializer<'de> {
        let b: [u8; 32] = serde::Deserialize::deserialize(d)?;
        CompressedRistretto(b).decompress().ok_or_else(|| de::Error::custom("Invalid RistrettoPoint"))
    }
}

pub mod scalar_vec_serde {
    use super::*;
    pub fn serialize<S>(v: &Vec<Scalar>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.collect_seq(v.iter().map(|c: &Scalar| c.to_bytes())) 
    }
    
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<Scalar>, D::Error>
    where D: Deserializer<'de> {
        let raw: Vec<[u8; 32]> = serde::Deserialize::deserialize(d)?;
        raw.into_iter().map(|b| {
            Scalar::from_canonical_bytes(b).ok_or_else(|| de::Error::custom("Invalid Scalar"))
        }).collect()
    }
}
