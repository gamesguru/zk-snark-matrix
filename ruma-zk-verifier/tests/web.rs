//! Test suite for the WebAssembly verify client.
#![cfg(target_arch = "wasm32")]

use serde::Deserialize;
use wasm_bindgen_test::*;
use zk_matrix_wasm::verify_matrix_join;

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Deserialize)]
struct SP1ProofMock {
    #[serde(rename = "Groth16")]
    pub groth16: Option<MockGroth16Proof>,
}

#[derive(Deserialize)]
struct MockGroth16Proof {
    encoded_proof: String,
}

#[derive(Deserialize)]
struct SP1ProofWithPublicValuesMock {
    proof: SP1ProofMock,
    public_values: Vec<u8>,
}

#[wasm_bindgen_test]
fn test_groth16_verification() {
    // We expect the CI pipeline to execute the host and generate a valid proof inside the workspace `res` folder
    let proof_bytes_with_io = include_bytes!("../../../res/proof-with-io.bin");

    // Parse the binary Payload emitted by SP1
    let payload: SP1ProofWithPublicValuesMock = bincode::deserialize(proof_bytes_with_io)
        .expect("Failed to deserialize STARK/zkVM binary proof emitted by Host");

    let groth16_wrapper = payload.proof.groth16.expect(
        "The emitted proof was a Core STARK. Did you forget to set SP1_GROTH16=true in the runner?",
    );

    // Convert hex string proof to bytes
    let proof_bytes =
        hex::decode(groth16_wrapper.encoded_proof).expect("Failed to decode Groth16 Hex proof");

    // SP1 matrix join generates a known VK hash for its own logic
    // We read it from the pre-compiled guest vkey
    let vkey_hash = include_str!("../../../res/vk_hash.txt");
    let clean_hash = vkey_hash.trim();

    // Pass the payload through our WASM verifier
    let success = verify_matrix_join(&proof_bytes, &payload.public_values, clean_hash);

    assert!(
        success,
        "WASM Binding failed to authenticate valid SP1 Groth16 wrapper!"
    );
}
