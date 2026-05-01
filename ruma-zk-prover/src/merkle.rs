//! Data Availability (DA) Merkle commitment for the public journal.
//!
//! The DA root is a Keccak-256 Merkle tree built over a **deterministically
//! sorted** array of event IDs. Because the sort order is canonical (using
//! the same tie-breaking rules as state resolution), any two servers holding
//! the same event set will compute the same root — regardless of network
//! arrival order.
//!
//! If the roots diverge, the servers do not share the same state, and the
//! verifier should query federation for missing events before accepting
//! any proof.

use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 of arbitrary data.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Build a Merkle root over a slice of event ID strings.
///
/// The event IDs must already be in deterministic (canonical) order.
/// Leaf nodes are Keccak-256(event_id). Internal nodes are
/// Keccak-256(left || right). The tree is padded with zero hashes
/// to the next power of 2.
pub fn build_merkle_root(event_ids: &[String]) -> [u8; 32] {
    if event_ids.is_empty() {
        return [0u8; 32];
    }

    // Leaf layer: hash each event_id
    let n = event_ids.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = event_ids
        .iter()
        .map(|id| keccak256(id.as_bytes()))
        .collect();

    // Pad to power of 2 with zero hashes
    layer.resize(n, [0u8; 32]);

    // Build tree bottom-up
    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut hasher = Keccak::v256();
            let mut parent = [0u8; 32];
            hasher.update(&pair[0]);
            hasher.update(&pair[1]);
            hasher.finalize(&mut parent);
            next_layer.push(parent);
        }
        layer = next_layer;
    }

    layer[0]
}

/// Sort event IDs deterministically for DA commitment.
///
/// For now, this uses lexicographic order on event_id strings.
/// In production, this should use the full Kahn sort output order
/// from `ruma-lean::lean_kahn_sort`.
pub fn canonical_sort(event_ids: &mut [String]) {
    event_ids.sort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_empty() {
        let root = build_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_single() {
        let ids = vec!["$event1:example.com".to_string()];
        let root = build_merkle_root(&ids);
        assert_eq!(root, keccak256(b"$event1:example.com"));
    }

    #[test]
    fn test_merkle_deterministic() {
        let ids = vec![
            "$aaa:example.com".to_string(),
            "$bbb:example.com".to_string(),
            "$ccc:example.com".to_string(),
            "$ddd:example.com".to_string(),
        ];
        let root1 = build_merkle_root(&ids);
        let root2 = build_merkle_root(&ids);
        assert_eq!(root1, root2, "same input must produce same root");
    }

    #[test]
    fn test_merkle_order_matters() {
        let ids_a = vec![
            "$aaa:example.com".to_string(),
            "$bbb:example.com".to_string(),
        ];
        let ids_b = vec![
            "$bbb:example.com".to_string(),
            "$aaa:example.com".to_string(),
        ];
        let root_a = build_merkle_root(&ids_a);
        let root_b = build_merkle_root(&ids_b);
        assert_ne!(
            root_a, root_b,
            "different order must produce different root"
        );
    }

    #[test]
    fn test_canonical_sort_deterministic() {
        let mut ids1 = vec![
            "$ccc:example.com".to_string(),
            "$aaa:example.com".to_string(),
            "$bbb:example.com".to_string(),
        ];
        let mut ids2 = vec![
            "$bbb:example.com".to_string(),
            "$ccc:example.com".to_string(),
            "$aaa:example.com".to_string(),
        ];
        canonical_sort(&mut ids1);
        canonical_sort(&mut ids2);
        assert_eq!(ids1, ids2, "canonical sort must be order-independent");

        let root1 = build_merkle_root(&ids1);
        let root2 = build_merkle_root(&ids2);
        assert_eq!(root1, root2, "same set must produce same DA root");
    }
}
