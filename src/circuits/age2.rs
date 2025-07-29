use ark_ff::{Fp, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

#[derive(Clone)]
// 나이 검증을 위한 circuit 구조체
// age가 19 이상인 경우에만 c = a * b를 강제 (age < 19인 경우 c ?= a * b는 수행되지 않음)
// if age >= 19
//    c ?= a * b
// else
//    do nothing

pub struct AgeCircuit2<F: PrimeField> {
    // instance
    pub age: Option<F>,
    pub c: Option<F>,
    // witness
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AgeCircuit2<F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        let age_var = FpVar::new_input(cs.clone(), || {
            self.age.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let age19 = F::from_str("19").unwrap_or_default();
        let age19_var = FpVar::new_constant(cs.clone(), age19)?;

        let is_age_ge_19 = age_var.is_cmp(&age19_var, std::cmp::Ordering::Greater, true)?;
        let c_var = FpVar::new_input(cs.clone(), || {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let a_var = FpVar::new_witness(cs.clone(), || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b_var = FpVar::new_witness(cs.clone(), || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // age가 19 이상인 경우에만 c = a * b를 강제
        c_var.conditional_enforce_equal(&(a_var * b_var), &is_age_ge_19)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::circuits::age2::AgeCircuit2;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::SNARK;
    use ark_ff::Fp;
    use ark_std::test_rng;
    use rand::{RngCore, SeedableRng};
    use std::str::FromStr;

    #[test]
    fn test_age1_circuit_groth16() {
        // Groth16: setup -> prove -> verify
        // setup: circuit의 제약조건을 기반으로 proving key와 verification key를 생성
        // prove: public input과 witness, proving key로부터 증명을 생성
        // verify: 증명과 verification key, public input으로부터 증명이 유효한지 확인

        // Groth16의 setup 및 proof는 random 값을 필요로 함
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let age: ark_bn254::Fr = ark_ff::Fp::from_str("20").unwrap();

        let a: Fr = Fp::from_str("2").unwrap();
        let b: Fr = Fp::from_str("4").unwrap();

        let c: Fr = Fp::from_str("8").unwrap();

        let test_circuit = AgeCircuit2 {
            age: Some(age),
            c: Some(c),
            a: Some(a),
            b: Some(b),
        };

        // Groth16의 setup: proving key (evaluation key)와 verification key를 생성
        let (pk, vk) =
            ark_groth16::Groth16::<Bn254>::circuit_specific_setup(test_circuit.clone(), rng)
                .unwrap();

        // Prover: "20"이라는 값에 dependent한 증명을 생성
        let proof = ark_groth16::Groth16::<Bn254>::prove(&pk, test_circuit, rng).unwrap();

        // Verifier: 증명이 유효한지 확인
        // public input은 없으므로 빈 벡터를 전달
        let result = ark_groth16::Groth16::<Bn254>::verify(&vk, &[age, c], &proof).unwrap();
        assert!(result, "Proof should be valid");
    }
}
