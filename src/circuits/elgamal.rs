use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::CurveVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

use crate::gadgets::public_encryptions::constraints::AsymmetricEncryptionGadget;
use crate::gadgets::public_encryptions::elgamal;
#[derive(Clone)]
pub struct ElgamalCircuit<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    // Constants
    pub g: elgamal::Parameters<C>,

    // statements
    pub pk: Option<elgamal::PublicKey<C>>,
    pub ct: Option<elgamal::Ciphertext<C>>,

    // witnesses
    pub m: Option<elgamal::Plaintext<C>>,
    pub r: Option<elgamal::Randomness<C>>,

    pub _curve_var: PhantomData<GG>,
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for ElgamalCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        // constants
        let g = elgamal::constraints::ParametersVar::new_constant(cs.clone(), self.g)?;

        // statements
        let pk = elgamal::constraints::PublicKeyVar::new_input(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ct = elgamal::constraints::OutputVar::new_input(cs.clone(), || {
            self.ct.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // witness
        let m = elgamal::constraints::PlaintextVar::new_witness(cs.clone(), || {
            self.m.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r = elgamal::constraints::RandomnessVar::new_witness(cs.clone(), || {
            self.r.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let result_var = elgamal::constraints::ElGamalEncGadget::<C, GG>::encrypt(&g, &m, &r, &pk)?;

        result_var.enforce_equal(&ct)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_std::{UniformRand, test_rng};
    use rand::{RngCore, SeedableRng};

    use crate::gadgets::public_encryptions::AsymmetricEncryptionScheme;
    use crate::gadgets::public_encryptions::elgamal::Randomness;
    use crate::{circuits::elgamal::ElgamalCircuit, gadgets::public_encryptions::elgamal};

    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type Enc = elgamal::ElGamal<C>;

    #[test]
    fn test_mul() {
        let rng = &mut test_rng();

        let parameters = Enc::setup(rng).unwrap();
        let (pk, _) = Enc::keygen(&parameters, rng).unwrap();
        let msg = C::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let ct = Enc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        let test_circuit: ElgamalCircuit<C, GG> = ElgamalCircuit {
            g: parameters,
            pk: Some(pk),
            ct: Some(ct),
            m: Some(msg),
            r: Some(randomness),
            _curve_var: std::marker::PhantomData,
        };
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_groth16_elgamal() {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let parameters = Enc::setup(rng).unwrap();
        let (public_key, _) = Enc::keygen(&parameters, rng).unwrap();
        let msg = C::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let ct = Enc::encrypt(&parameters, &public_key, &msg, &randomness).unwrap();

        let test_circuit: ElgamalCircuit<C, GG> = ElgamalCircuit {
            g: parameters,
            pk: Some(public_key),
            ct: Some(ct),
            m: Some(msg),
            r: Some(randomness),
            _curve_var: std::marker::PhantomData,
        };

        let (pk, vk) = Groth16::<Bn254>::setup(test_circuit.clone(), rng).unwrap();

        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let verify_inputs = [public_key.x, public_key.y, ct.0.x, ct.0.y, ct.1.x, ct.1.y];

        let proof = Groth16::<Bn254>::prove(&pk, test_circuit, rng).unwrap();

        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &verify_inputs, &proof).unwrap(),)
    }
}
