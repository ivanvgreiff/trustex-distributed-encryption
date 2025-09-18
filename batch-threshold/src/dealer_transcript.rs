// batch-threshold/src/dealer_transcript.rs
#![cfg(feature = "tee-dealer")]

use crate::dealer::CRS;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;

/// Canonical bytes over which the dev enclave signs:
/// H( batch_size || n || t || CRS || pk || per_share_pks || party_ids || [OPTIONALLY lengths] )
pub fn attested_dealer_message_bytes<E: Pairing>(
    batch_size: usize,
    n: usize,
    t: usize,
    crs: &CRS<E>,
    commitments: &super::attested_dealer::DealerCommitments<E>,
    shares: &Vec<super::attested_dealer::ShareForParty<E>>,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(batch_size as u64).to_le_bytes());
    v.extend_from_slice(&(n as u64).to_le_bytes());
    v.extend_from_slice(&(t as u64).to_le_bytes());

    // CRS: powers_of_g (G1^B), htau (G2), y (G1^B) -- uses ark CanonicalSerialize
    for p in &crs.powers_of_g {
        p.serialize_compressed(&mut v).unwrap();
    }
    crs.htau.serialize_compressed(&mut v).unwrap();
    for yi in &crs.y {
        yi.serialize_compressed(&mut v).unwrap();
    }

    commitments.pk.serialize_compressed(&mut v).unwrap();
    v.extend_from_slice(&(commitments.per_share_pks.len() as u64).to_le_bytes());
    for (pid, hshare) in &commitments.per_share_pks {
        v.extend_from_slice(&pid.0.to_le_bytes());
        hshare.serialize_compressed(&mut v).unwrap();
    }

    v.extend_from_slice(&(shares.len() as u64).to_le_bytes());
    for s in shares {
        v.extend_from_slice(&s.id.0.to_le_bytes());
        // shares are secret values; we DO NOT include their scalars in the signature message.
        // Including only the ids here avoids binding the signature to secrets.
    }
    v
}

/// Fixed-size digest used for Ed25519 signing in dev mode.
pub fn digest32(msg: &[u8]) -> [u8; 32] {
    blake3::hash(msg).into()
}
