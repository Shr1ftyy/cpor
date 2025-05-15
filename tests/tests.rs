// tests.rs
use cpor::{generate_challenge, generate_proof, generate_tags, keygen, verify};

use bls12_381::Scalar;
use ff::Field;

// Honest prover stores full data
struct HonestProver {
    data_blocks: Vec<Scalar>,
    tags: Vec<bls12_381::G1Projective>,
}

impl HonestProver {
    fn new(data_blocks: Vec<Scalar>, x: &Scalar) -> Self {
        let tags = generate_tags(&data_blocks, x);
        Self { data_blocks, tags }
    }

    // Generate proof honestly
    fn generate_proof(
        &self,
        indices: &[usize],
        coefficients: &[Scalar],
    ) -> (bls12_381::G1Projective, Scalar) {
        generate_proof(indices, coefficients, &self.data_blocks, &self.tags)
    }
}

// Cheating prover stores only a subset of data blocks, fakes rest
struct CheatingProver {
    data_blocks: Vec<Option<Scalar>>, // None means missing
    tags: Vec<bls12_381::G1Projective>,
}

impl CheatingProver {
    fn new(full_data: &[Scalar], x: &Scalar, to_keep: &[usize]) -> Self {
        // Keep only some blocks, None for others
        let mut data_blocks = Vec::with_capacity(full_data.len());
        for i in 0..full_data.len() {
            if to_keep.contains(&i) {
                data_blocks.push(Some(full_data[i]));
            } else {
                data_blocks.push(None);
            }
        }
        let tags = generate_tags(full_data, x); // tags generated on full data
        Self { data_blocks, tags }
    }

    // Try to generate proof; for missing blocks, substitute zero scalar (cheating)
    fn generate_proof(
        &self,
        indices: &[usize],
        coefficients: &[Scalar],
    ) -> (bls12_381::G1Projective, Scalar) {
        let mut sigma = bls12_381::G1Projective::identity();
        let mut mu = Scalar::zero();

        for (&i, &v_i) in indices.iter().zip(coefficients.iter()) {
            sigma += self.tags[i] * v_i;

            // Use real data if available, else zero (cheating)
            if let Some(m_i) = self.data_blocks[i] {
                mu += m_i * v_i;
            } else {
                mu += Scalar::zero(); // cheat here
            }
        }

        (sigma, mu)
    }
}

#[test]
fn test_honest_prover() {
    let (x, v) = keygen();
    let data_blocks: Vec<Scalar> = (0..10)
        .map(|_| Scalar::random(&mut rand::rngs::OsRng))
        .collect();
    let prover = HonestProver::new(data_blocks.clone(), &x);

    let (indices, coefficients) = generate_challenge(data_blocks.len(), 5);

    let (sigma, mu) = prover.generate_proof(&indices, &coefficients);

    assert!(verify(&sigma, &mu, &indices, &coefficients, &v));
}

#[test]
fn test_cheating_prover_missing_blocks() {
    let (x, v) = keygen();
    let data_blocks: Vec<Scalar> = (0..10)
        .map(|_| Scalar::random(&mut rand::rngs::OsRng))
        .collect();

    // Cheater keeps only first 5 blocks, discards rest
    let cheating_prover = CheatingProver::new(&data_blocks, &x, &(0..5).collect::<Vec<_>>());

    // Run multiple challenges to detect cheating with high probability
    for _ in 0..10 {
        let (indices, coefficients) = generate_challenge(data_blocks.len(), 5);
        let (sigma, mu) = cheating_prover.generate_proof(&indices, &coefficients);
        let valid = verify(&sigma, &mu, &indices, &coefficients, &v);

        // Because cheater returns zero for missing data, verification should fail most times
        // There's a small chance a random combination coincidentally passes; running multiple times reduces this.
        if indices.iter().any(|&i| i >= 5) {
            assert!(!valid, "Cheating prover passed verification incorrectly!");
        }
    }
}

#[test]
fn test_cheating_prover_caching() {
    let (x, v) = keygen();
    let data_blocks: Vec<Scalar> = (0..10)
        .map(|_| Scalar::random(&mut rand::rngs::OsRng))
        .collect();

    let prover = HonestProver::new(data_blocks.clone(), &x);

    // Generate a challenge and proof once
    let (indices, coefficients) = generate_challenge(data_blocks.len(), 5);
    let (sigma, mu) = prover.generate_proof(&indices, &coefficients);

    // Cheating prover caches this proof and tries to reuse it for a different challenge
    let (indices2, coefficients2) = generate_challenge(data_blocks.len(), 5);

    // Cheater reuses old proof even if challenge changes (which it shouldn't)
    // We test that verification fails in this case

    let valid = verify(&sigma, &mu, &indices2, &coefficients2, &v);

    assert!(
        !valid,
        "Cached proof should not verify for a different challenge!"
    );
}
