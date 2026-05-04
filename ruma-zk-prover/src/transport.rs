//! Federation transport types for the ZK State Proof endpoint.
//!
//! Defines the JSON schema types matching
//! `GET /_matrix/federation/unstable/org.matrix.msc0000/zk_state_proof/{roomId}`
//!
//! These types are transport-layer only — no homeserver plugin code.
//! They enable serialization/deserialization of proofs for federation.

use serde::{Deserialize, Serialize};

use crate::stark::StarkProof;

/// The full response body for the ZK state proof endpoint.
///
/// Matches the MSC0000 JSON schema exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkStateProofResponse {
    /// Matrix room version (e.g., "12").
    pub room_version: String,
    /// SHA-256 hash of the verification key: `sha256:<hex_digest>`.
    pub vk_hash: String,
    /// The cryptographic checkpoint (rollup).
    pub checkpoint: ZkCheckpoint,
    /// Unverified event delta since the checkpoint.
    pub delta: ZkDelta,
}

/// A cryptographic checkpoint (rollup) over room state history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCheckpoint {
    /// The Matrix event ID at the deterministic cutoff point.
    pub event_id: String,
    /// Public inputs committed to the STARK proof's Fiat-Shamir transcript.
    pub public_journal: PublicJournalTransport,
    /// Base64-encoded bincode-serialized STARK proof payload.
    pub zk_proof_bytes: String,
    /// The generating server's signature over the public journal.
    pub prover_signature: ProverSignature,
}

/// Public journal in the transport format (hex-encoded fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicJournalTransport {
    /// Keccak-256 Merkle root over the canonically sorted input event set.
    pub da_root: String,
    /// Keccak-256 hash over the resolved state output.
    pub state_root: String,
    /// Keccak-256 identity binding hash.
    pub h_auth: String,
    /// Number of events in the proven DAG.
    pub n_events: u64,
    /// `Keccak-256(server_name)` of the generating homeserver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_id: Option<String>,
    /// Unix epoch (seconds) when the proof was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_timestamp: Option<u64>,
    /// Inclusive event index range this proof covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_range: Option<[u64; 2]>,
    /// `state_root` of the previous epoch proof (`null` for genesis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_base: Option<String>,
    /// Hashes of sub-proofs recursively folded into this proof.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_proofs: Vec<String>,
}

/// Server signature over the canonical JSON public journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverSignature {
    /// The generating server's name (e.g., "matrix.org").
    pub server_name: String,
    /// The signing key identifier (e.g., "ed25519:abc123").
    pub key_id: String,
    /// Base64-encoded signature bytes.
    pub signature: String,
}

/// The unverified event delta since the checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkDelta {
    /// Standard Matrix state events (PDUs) since the checkpoint.
    pub recent_state_events: Vec<serde_json::Value>,
}

/// Encode a STARK proof into a base64 string for federation transport.
pub fn encode_proof_bytes(proof: &StarkProof) -> Result<String, String> {
    let bytes = bincode::serialize(proof).map_err(|e| format!("serialize: {e}"))?;
    Ok(base64_encode(&bytes))
}

/// Decode a base64 STARK proof from federation transport.
pub fn decode_proof_bytes(encoded: &str) -> Result<StarkProof, String> {
    let bytes = base64_decode(encoded)?;
    bincode::deserialize(&bytes).map_err(|e| format!("deserialize: {e}"))
}

/// Build a `ZkStateProofResponse` from a proof and metadata.
pub fn build_response(
    proof: &StarkProof,
    room_version: &str,
    vk_hash: &str,
    event_id: &str,
    server_name: &str,
) -> Result<ZkStateProofResponse, String> {
    let journal = &proof.journal;

    Ok(ZkStateProofResponse {
        room_version: room_version.to_string(),
        vk_hash: vk_hash.to_string(),
        checkpoint: ZkCheckpoint {
            event_id: event_id.to_string(),
            public_journal: PublicJournalTransport {
                da_root: hex::encode(journal.da_root),
                state_root: hex::encode(journal.state_root),
                h_auth: hex::encode(journal.h_auth),
                n_events: journal.n_events,
                prover_id: None,
                proof_timestamp: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                epoch_range: Some([0, journal.n_events]),
                merge_base: None,
                parent_proofs: vec![],
            },
            zk_proof_bytes: encode_proof_bytes(proof)?,
            prover_signature: ProverSignature {
                server_name: server_name.to_string(),
                key_id: "ed25519:unsigned".to_string(),
                signature: String::new(), // Placeholder — real signing is homeserver-specific
            },
        },
        delta: ZkDelta {
            recent_state_events: vec![],
        },
    })
}

// ── Base64 helpers (no external dependency) ──

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 character: {c}")),
        }
    }

    let bytes = encoded.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let n = (val(chunk[0])? << 18)
            | (val(chunk[1])? << 12)
            | (val(chunk[2])? << 6)
            | val(chunk[3])?;
        result.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            result.push((n >> 8) as u8);
        }
        if chunk[3] != b'=' {
            result.push(n as u8);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::keccak256;
    use crate::stark::PublicJournal;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world, this is a test of base64 encoding";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_proof_encode_decode_roundtrip() {
        use crate::field::GF2;
        use crate::trace::ExecutionTrace;
        use crate::waksman::BenesNetwork;

        let perm: Vec<usize> = (0..8).rev().collect();
        let network = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<GF2> = (0..8).map(|i| GF2::new(i as u8 & 1)).collect();
        let trace = ExecutionTrace::build(&inputs, &network);

        let journal = PublicJournal {
            da_root: keccak256(b"test-da"),
            state_root: keccak256(b"test-state"),
            h_auth: keccak256(b"test-auth"),
            n_events: 8,
        };

        let proof = crate::stark::prove(&trace, journal);
        let encoded = encode_proof_bytes(&proof).unwrap();
        let decoded = decode_proof_bytes(&encoded).unwrap();

        // Verify the decoded proof
        assert!(crate::stark::verify(&decoded).is_ok());
    }

    #[test]
    fn test_build_response_json() {
        use crate::field::GF2;
        use crate::trace::ExecutionTrace;
        use crate::waksman::BenesNetwork;

        let perm: Vec<usize> = (0..8).rev().collect();
        let network = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<GF2> = (0..8).map(|i| GF2::new(i as u8 & 1)).collect();
        let trace = ExecutionTrace::build(&inputs, &network);

        let journal = PublicJournal {
            da_root: keccak256(b"test-da"),
            state_root: keccak256(b"test-state"),
            h_auth: keccak256(b"test-auth"),
            n_events: 8,
        };

        let proof = crate::stark::prove(&trace, journal);
        let response = build_response(
            &proof,
            "12",
            "sha256:abc123",
            "$cutoff:example.com",
            "example.com",
        )
        .unwrap();

        // Should serialize to JSON
        let json = serde_json::to_string_pretty(&response).unwrap();
        assert!(json.contains("\"room_version\": \"12\""));
        assert!(json.contains("\"vk_hash\": \"sha256:abc123\""));
        assert!(json.contains("\"n_events\": 8"));
        assert!(json.contains("\"server_name\": \"example.com\""));

        // Should deserialize back
        let parsed: ZkStateProofResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.room_version, "12");

        // Decoded proof should verify
        let decoded_proof = decode_proof_bytes(&parsed.checkpoint.zk_proof_bytes).unwrap();
        assert!(crate::stark::verify(&decoded_proof).is_ok());
    }
}
