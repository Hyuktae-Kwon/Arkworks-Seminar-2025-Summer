use super::*;
use crate::gadgets::public_encryptions::constraints::AsymmetricEncryptionGadget;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::{
    ToBitsGadget,
    prelude::{AllocVar, AllocationMode, Boolean, CurveVar, EqGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use std::{borrow::Borrow, marker::PhantomData};

#[derive(Clone)]
// 증명하고자 하는 값들은 Elliptic Curve (Bn254)의 Scalar Field의 원소여야 함
// ElGamal은 Elliptic curve 기반이며 base field와 scalar field 모두 사용해야 함
// 문제 발생: 하나의 Bn254 curve로 ElGamal의 base field와 scalar field를 표현해야 함
// 해결책: ElGamal에 ed_on_bn254라는 curve를 사용 (이 curve의 base field는 Bn254의 Scalar Field와 동일함)
// m*(pk^r) 꼴에서 r 등의 scalar field 원소는 ed_on_bn254의 Scalar Field의 원소로 표현
// m, pk 등의 base field 원소는 ed_on_bn254의 base field (즉, Bn254의 Scalar Field)의 원소로 표현
// ed_on_bn254의 base field는 UInt8로 표현 (서로 다른 curve이기 때문에 8비트 단위로 쪼개서 표현)

pub struct RandomnessVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: CurveGroup,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| b.borrow().0)
            .unwrap_or(C::ScalarField::zero())
            .serialize_compressed(&mut r)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub generator: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, C::BaseField> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct PlaintextVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub plaintext: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Plaintext<C>, C::BaseField> for PlaintextVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            plaintext,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct PublicKeyVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub pk: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, C::BaseField> for PublicKeyVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pk = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            pk,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct OutputVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub c1: GG,
    pub c2: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Ciphertext<C>, C::BaseField> for OutputVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let c2 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<C::BaseField> for OutputVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, C::BaseField>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<C::BaseField>, SynthesisError> {
        self.c1.is_eq(&other.c1)?.and(&self.c2.is_eq(&other.c2)?)
    }
}

#[derive(Clone)]
pub struct ElGamalEncGadget<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> AsymmetricEncryptionGadget<ElGamal<C>, C::BaseField> for ElGamalEncGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type ParametersVar = ParametersVar<C, GG>;
    type PlaintextVar = PlaintextVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type RandomnessVar = RandomnessVar<C::BaseField>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = randomness*pk
        let s = public_key.pk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

        // compute c2 = m + s
        let c2 = message.plaintext.clone() + s;

        Ok(Self::OutputVar {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::{UniformRand, test_rng};

    use ark_ed_on_bn254::{EdwardsProjective, Fq, constraints::EdwardsVar};

    use crate::gadgets::public_encryptions::AsymmetricEncryptionScheme;
    use crate::gadgets::public_encryptions::constraints::AsymmetricEncryptionGadget;
    use crate::gadgets::public_encryptions::elgamal::{
        ElGamal, Randomness, constraints::ElGamalEncGadget,
    };
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type MyEnc = ElGamal<EdwardsProjective>;
        type MyGadget = ElGamalEncGadget<EdwardsProjective, EdwardsVar>;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (pk, _) = MyEnc::keygen(&parameters, rng).unwrap();
        let msg = EdwardsProjective::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var =
            MyGadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c1.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
