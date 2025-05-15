use bls12_381::Scalar;
use cpor::{generate_challenge, generate_proof, generate_tags, keygen, verify};
use ff::Field;
use rand::rngs::OsRng;

fn main() {
    // Step 1: Key generation by client
    let (x, v) = keygen();

    // Step 2: Split file into n data blocks (simulated here as random scalars)
    let data_blocks: Vec<Scalar> = (0..10).map(|_| Scalar::random(&mut OsRng)).collect();

    // Step 3: Compute tags for each data block
    let tags = generate_tags(&data_blocks, &x);

    // Step 4: Verifier issues a challenge (e.g. query 3 blocks)
    let (indices, coefficients) = generate_challenge(data_blocks.len(), 3);

    // Step 5: Prover computes a compact proof (σ, μ)
    let (sigma, mu) = generate_proof(&indices, &coefficients, &data_blocks, &tags);

    // Step 6: Verifier checks the proof
    let is_valid = verify(&sigma, &mu, &indices, &coefficients, &v);

    println!("Proof is valid: {}", is_valid);
}
