//! DEV ingress service: verifies the same relation as validators and returns a signed attestation.
//! In production, wrap this in RA-TLS and plug a real AttestationVerifier on the client side.

use anyhow::Result;
use axum::{routing::post, Json, Router};
use batch_threshold::{
    verification::verify_ciphertext_relation, 
    envelope::*
};
use ed25519_dalek::{SigningKey, Signer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type ReplayFilter = Arc<Mutex<HashMap<u64, std::collections::HashSet<[u8; 32]>>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // DEV key (do not use in prod). In real TEE, the key is bound to RA quote.
    let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let replay_filter: ReplayFilter = Arc::new(Mutex::new(HashMap::new()));
    
    let app_state = AppState {
        signing_key: sk,
        replay_filter,
    };
    
    // serve simple JSON API
    let app = Router::new()
        .route("/attest", post(attest_handler))
        .with_state(app_state);
        
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    println!("Ingress service listening on http://127.0.0.1:8080");
    
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    signing_key: SigningKey,
    replay_filter: ReplayFilter,
}

async fn attest_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Json<AttestResponse> {
    use batch_threshold::encryption::Ciphertext;
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    
    type E = Bls12_381;
    
    // 1) Deserialize Ciphertext and public params
    let ct: Ciphertext<E> = match CanonicalDeserialize::deserialize_compressed(&req.ct[..]) {
        Ok(ct) => ct,
        Err(_) => {
            return Json(AttestResponse {
                sig: serde_bytes::ByteBuf::new(),
                quote: serde_bytes::ByteBuf::new(),
                ts_unix_ms: 0,
                nonce: [0; 16],
                success: false,
                error: Some("Failed to deserialize ciphertext".to_string()),
            });
        }
    };
    
    let pk: <E as ark_ec::pairing::Pairing>::G2 = match CanonicalDeserialize::deserialize_compressed(&req.pk[..]) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(AttestResponse {
                sig: serde_bytes::ByteBuf::new(),
                quote: serde_bytes::ByteBuf::new(),
                ts_unix_ms: 0,
                nonce: [0; 16],
                success: false,
                error: Some("Failed to deserialize public key".to_string()),
            });
        }
    };
    
    let htau: <E as ark_ec::pairing::Pairing>::G2 = match CanonicalDeserialize::deserialize_compressed(&req.htau[..]) {
        Ok(htau) => htau,
        Err(_) => {
            return Json(AttestResponse {
                sig: serde_bytes::ByteBuf::new(),
                quote: serde_bytes::ByteBuf::new(),
                ts_unix_ms: 0,
                nonce: [0; 16],
                success: false,
                error: Some("Failed to deserialize htau".to_string()),
            });
        }
    };
    
    // 2) Run verify_ciphertext_relation(ct, htau, pk)
    if let Err(_) = verify_ciphertext_relation(&ct, &htau, &pk) {
        return Json(AttestResponse {
            sig: serde_bytes::ByteBuf::new(),
            quote: serde_bytes::ByteBuf::new(),
            ts_unix_ms: 0,
            nonce: [0; 16],
            success: false,
            error: Some("Ciphertext verification failed".to_string()),
        });
    }
    
    // 3) Enforce per-epoch Bloom filter on (x̂, H(S)) to block copies
    let x_hash = blake3::hash(&{
        let mut buf = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&ct.x, &mut buf).unwrap();
        buf
    });
    let s_hash = blake3::hash(&{
        let mut buf = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&ct.gs, &mut buf).unwrap();
        buf
    });
    let mut combined_input = Vec::new();
    combined_input.extend_from_slice(x_hash.as_bytes());
    combined_input.extend_from_slice(s_hash.as_bytes());
    let combined_hash = blake3::hash(&combined_input);
    let replay_key: [u8; 32] = *combined_hash.as_bytes();
    
    {
        let mut filter = state.replay_filter.lock().unwrap();
        let epoch_filter = filter.entry(req.eid).or_insert_with(std::collections::HashSet::new);
        if epoch_filter.contains(&replay_key) {
            return Json(AttestResponse {
                sig: serde_bytes::ByteBuf::new(),
                quote: serde_bytes::ByteBuf::new(),
                ts_unix_ms: 0,
                nonce: [0; 16],
                success: false,
                error: Some("Replay detected - ciphertext already seen in this epoch".to_string()),
            });
        }
        epoch_filter.insert(replay_key);
    }
    
    // 4) Construct AttestedMessage and sign
    let ts_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let nonce: [u8; 16] = rand::random();
    
    // Create envelope for message construction
    let envelope = Envelope {
        eid: EpochId(req.eid),
        ct,
        att: Some(IngressAttestation {
            sig: Vec::new(), // placeholder
            quote: Vec::new(), // empty in dev mode
            ts_unix_ms,
            nonce,
        }),
    };
    
    let message_bytes = batch_threshold::attestation::attested_message_bytes(&envelope);
    let signature = state.signing_key.sign(&message_bytes);
    
    // 5) Return {sig, dev_quote, ts, nonce}
    Json(AttestResponse {
        sig: serde_bytes::ByteBuf::from(signature.to_bytes().to_vec()),
        quote: serde_bytes::ByteBuf::new(), // empty in dev mode
        ts_unix_ms,
        nonce,
        success: true,
        error: None,
    })
}

/// Request/response types (use serde for simplicity in dev).
#[derive(serde::Deserialize)]
struct AttestRequest {
    eid: u64,
    ct: serde_bytes::ByteBuf,
    pk: serde_bytes::ByteBuf,
    htau: serde_bytes::ByteBuf,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    sig: serde_bytes::ByteBuf,
    quote: serde_bytes::ByteBuf, // empty in dev; RA in prod
    ts_unix_ms: u64,
    nonce: [u8; 16],
    success: bool,
    error: Option<String>,
}
