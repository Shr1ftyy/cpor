// Import cryptographic primitives from the BLS12-381 pairing-friendly curve
use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};

// Generate a secret/public key pair
pub fn keygen() -> (Scalar, G2Projective) {
    let mut rng = OsRng;
    let x = Scalar::random(&mut rng); // secret key
    let g = G2Projective::generator(); // public generator in G2
    let v = g * x; // public key: v = g^x
    (x, v)
}

// Deterministically hash an index to a scalar, reducing mod q
pub fn hash_to_scalar(i: usize) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(i.to_be_bytes());
    let hash = hasher.finalize();

    // Convert 32-byte hash to a 64-byte input to ensure it lies in the scalar field
    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide_bytes)
}

// Map index to a point on G1: H(i) = g1^{hash(i)}
pub fn hash_to_g1(i: usize) -> G1Projective {
    G1Projective::generator() * hash_to_scalar(i)
}

// Generate tags t_i = (H(i) * g^{m_i})^x for each data block m_i
pub fn generate_tags(data_blocks: &[Scalar], x: &Scalar) -> Vec<G1Projective> {
    data_blocks
        .iter()
        .enumerate()
        .map(|(i, m_i)| {
            let h_i = hash_to_g1(i); // hash index to G1
            let g = G1Projective::generator(); // base generator in G1
            let temp = h_i + (g * m_i); // H(i) * g^{m_i}
            temp * x // tag = (H(i) * g^{m_i})^x
        })
        .collect()
}

// Generate a random challenge: pick t random indices and coefficients
pub fn generate_challenge(n: usize, t: usize) -> (Vec<usize>, Vec<Scalar>) {
    let mut rng = OsRng;
    let indices: Vec<usize> = (0..n).collect();
    let selected_indices = indices.choose_multiple(&mut rng, t).cloned().collect();
    let coefficients = (0..t).map(|_| Scalar::random(&mut rng)).collect();
    (selected_indices, coefficients)
}

// Generate a proof (sigma, mu) for a subset of data blocks and tags
pub fn generate_proof(
    indices: &[usize],
    coefficients: &[Scalar],
    data_blocks: &[Scalar],
    tags: &[G1Projective],
) -> (G1Projective, Scalar) {
    let mut sigma = G1Projective::identity(); // aggregated tag
    let mut mu: Scalar = Scalar::zero(); // linear combination of data blocks
    for (&i, &v_i) in indices.iter().zip(coefficients.iter()) {
        sigma += tags[i] * v_i; // σ = Π t_i^{v_i}
        mu += data_blocks[i] * v_i; // μ = Σ m_i * v_i
    }
    (sigma, mu)
}

// Verify the proof using pairings
pub fn verify(
    sigma: &G1Projective,
    mu: &Scalar,
    indices: &[usize],
    coefficients: &[Scalar],
    v: &G2Projective, // public key = g2^x
) -> bool {
    // Compute e(σ, g2)
    let lhs = pairing(&sigma.to_affine(), &G2Projective::generator().to_affine());

    // Compute product of H(i)^v_i * g1^μ
    let mut temp = G1Projective::identity();
    for (&i, &v_i) in indices.iter().zip(coefficients.iter()) {
        temp += hash_to_g1(i) * v_i;
    }
    temp += G1Projective::generator() * mu;

    // Compute e(H(i)^v_i * g1^μ, v)
    let rhs = pairing(&temp.to_affine(), &v.to_affine());

    // Valid proof iff both pairings are equal
    lhs == rhs
}
