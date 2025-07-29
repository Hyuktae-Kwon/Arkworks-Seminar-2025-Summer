use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::ConstraintSynthesizer;

#[derive(Clone)]
pub struct PolyCircuit<F: PrimeField> {
    // constants
    pub coeff: Option<Vec<F>>,
    // public input
    pub y: Option<F>,
    // witness
    pub x: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PolyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        let coeff_vars: Vec<FpVar<F>> = self
            .coeff
            .unwrap()
            .iter()
            .map(|c| FpVar::new_constant(cs.clone(), *c).unwrap())
            .collect();

        let x_var = FpVar::new_witness(cs.clone(), || {
            self.x
                .ok_or(ark_relations::r1cs::SynthesisError::AssignmentMissing)
        })?;

        let y_var = FpVar::new_input(cs.clone(), || {
            self.y
                .ok_or(ark_relations::r1cs::SynthesisError::AssignmentMissing)
        })?;

        let mut res_var = FpVar::new_constant(cs.clone(), F::zero())?;

        // x의 거듭제곱을 계산할 변수 (x^0 = 1 로 시작)
        let mut x_power_var = FpVar::one();

        for c_var in coeff_vars.iter() {
            // 현재 항을 계산합니다: c_i * x^i
            let term_var = c_var * &x_power_var;
            // 결과에 더합니다.
            res_var += term_var;

            // 다음 항을 위해 x의 거듭제곱을 업데이트합니다 (x^i -> x^(i+1))
            x_power_var *= &x_var;
        }

        // 계산된 결과가 공개 입력 `y`와 같은지 강제합니다.
        y_var.enforce_equal(&res_var)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bn::Bn;
    use ark_groth16::Groth16;
    use ark_std::{
        rand::{SeedableRng, rngs::StdRng},
        test_rng,
    };
    use rand::RngCore;

    #[test]
    fn test_poly_circuit_groth16() {
        // 증명하려는 statement: "나는 x^3 + x + 5 = 35 를 만족하는 x를 안다"
        // witness x=3
        // public input y=35
        // coefficients: [5, 1, 0, 1]
        let coeffs = vec![Fr::from(5), Fr::from(1), Fr::from(0), Fr::from(1)];
        let x = Fr::from(3);
        let y = Fr::from(35);

        let circuit = PolyCircuit {
            coeff: Some(coeffs),
            y: Some(y),
            x: Some(x),
        };

        // Setup
        let mut rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        // Prover
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Verifier
        let public_inputs = vec![y];
        let result = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

        assert!(result, "Proof should be valid");
    }
}
