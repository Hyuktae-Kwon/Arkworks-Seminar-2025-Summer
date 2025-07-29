use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

#[derive(Clone)]
// 나이 검증을 위한 circuit 구조체
pub struct AgeCircuit1<F: PrimeField> {
    // witness로 사용될 나이 값
    // Option 사용 이유:
    // 1) circuit setup을 할 때 None으로 초기화할 수 있게
    // 2) default 값으로 원치 않는 값이 들어가는 것을 방지
    pub age: Option<F>,
}

// Arkworks에서는 ConstraintSynthesizer trait을 구현하여 circuit에 값 할당 및 해당 값 간의 제약조건 정의
impl<F: PrimeField> ConstraintSynthesizer<F> for AgeCircuit1<F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        // circuit 밖의 값을 circuit 안에 할당 필요
        // convetion: circuit 안의 값에는 var을 붙임
        // new_input: public input을 할당
        // new_witness: witness를 할당
        // new_constant: constant를 할당
        let age_var = FpVar::new_witness(cs.clone(), || {
            self.age.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let age19 = F::from_str("19").unwrap_or_default();
        let age19_var = FpVar::new_constant(cs.clone(), age19)?;

        // age가 19보다 큰지 비교하는 제약 조건
        // enforce_cmp: 비교 연산 결과가 참이여야만 true를 반환하도록하는 constraint 추가
        age_var.enforce_cmp(&age19_var, std::cmp::Ordering::Greater, true)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::circuits::age1::AgeCircuit1;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::SNARK;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_std::test_rng;
    use rand::{RngCore, SeedableRng};
    use std::str::FromStr;

    // cargo test: 기본적으로 debug 모드로 실행
    // cargo test --release: release 모드로 실행
    // cargo test -- --nocapture: 테스트 출력이 보이도록 실행
    // 일반적으로 cargo test --release -- --nocapture로 실행
    #[test]
    // witness가 20인경우 age1 circuit이 satisfied 되는지 확인하는 테스트
    // Proof를 생성하는 것이 아니라, constraint가 만족되는지만 확인하는 테스트
    fn test_age1_circuit_cs() {
        let age: ark_bn254::Fr = ark_ff::Fp::from_str("20").unwrap();

        let test_circuit = AgeCircuit1 { age: Some(age) };
        // constraint system: circuit을 구성하는 값들과 제약조건들을 포함하는 구조체
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        // constraint의 개수를 출력
        println!("Constraints: {}", cs.num_constraints());
        // constraint가 만족되는지 확인
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_age1_circuit_groth16() {
        // Groth16: setup -> prove -> verify
        // setup: circuit의 제약조건을 기반으로 proving key와 verification key를 생성
        // prove: public input과 witness, proving key로부터 증명을 생성
        // verify: 증명과 verification key, public input으로부터 증명이 유효한지 확인

        // Groth16은 Elliptic Curve를 사용함
        // 증명하고자 하는 값들은 Elliptic Curve의 Scalar Field의 원소여야 함
        // 따라서 Bn254의 Scalar Field인 Fr를 사용

        // Groth16의 setup 및 proof는 random 값을 필요로 함
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // circuit의 setup을 위한 mock circuit 생성
        // Groth16의 circuit은 public input과 witnes와의 "관계"를 표현 때문에 값에 dependent 하지 않음
        // 따라서, mock circuit을 생성하여 setup을 수행
        // mock circuit에서는 아무 값을 사용해도 됨 (Groth16 circuit은 값에 dependent 하지 않으므로)
        let age_default: ark_bn254::Fr = ark_ff::Fp::from_str("0").unwrap();
        let mock_circuit = AgeCircuit1 {
            age: Some(age_default),
        };

        // Groth16의 setup: proving key (evaluation key)와 verification key를 생성
        let (pk, vk) =
            ark_groth16::Groth16::<Bn254>::circuit_specific_setup(mock_circuit, rng).unwrap();

        // 실제 증명에 사용할 witness 값
        let age: ark_bn254::Fr = ark_ff::Fp::from_str("20").unwrap();
        let test_circuit = AgeCircuit1 { age: Some(age) };

        // Prover: "20"이라는 값에 dependent한 증명을 생성
        let proof = ark_groth16::Groth16::<Bn254>::prove(&pk, test_circuit, rng).unwrap();

        // Verifier: 증명이 유효한지 확인
        // public input은 없으므로 빈 벡터를 전달
        let result = ark_groth16::Groth16::<Bn254>::verify(&vk, &[], &proof).unwrap();
        assert!(result, "Proof should be valid");
    }
}
