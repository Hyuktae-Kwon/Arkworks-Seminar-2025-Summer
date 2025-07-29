use std::marker::PhantomData;
use std::ops::Mul;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

use super::AsymmetricEncryptionScheme;

pub mod constraints;

pub struct ElGamal<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

#[derive(Clone)]
pub struct Randomness<C: CurveGroup>(pub C::ScalarField);
impl<C: CurveGroup> UniformRand for Randomness<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(C::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as CurveGroup>::Affine;

pub type Ciphertext<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

impl<C: CurveGroup> AsymmetricEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        let generator = C::rand(rng).into();
        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), ark_crypto_primitives::Error> {
        let secret_key: C::ScalarField = C::ScalarField::rand(rng);
        let public_key = pp.generator.mul(secret_key).into();
        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ark_crypto_primitives::Error> {
        let s = pk.mul(r.0).into();
        let c1 = pp.generator.mul(r.0).into();
        let c2 = (*message + s).into();

        Ok((c1, c2))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ark_crypto_primitives::Error> {
        let c1: <C as CurveGroup>::Affine = ciphertext.0;
        let c2: <C as CurveGroup>::Affine = ciphertext.1;

        let s = c1.mul(sk.0);
        let s_inv = -s;

        let m = c2 + s_inv;

        Ok(m.into_affine())
    }
}

#[cfg(test)]
mod test {
    use ark_ec::CurveGroup;
    use ark_std::{UniformRand, test_rng};

    use super::{ElGamal, Randomness};

    use crate::gadgets::public_encryptions::AsymmetricEncryptionScheme;

    type C = ark_ed_on_bn254::EdwardsProjective;

    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        let parameter = ElGamal::<C>::setup(rng).unwrap();
        let (pk, sk) = ElGamal::<C>::keygen(&parameter, rng).unwrap();

        let msg: <C as CurveGroup>::Affine = C::rand(rng).into();
        let r: Randomness<C> = Randomness::rand(rng);

        let cipher = ElGamal::<C>::encrypt(&parameter, &pk, &msg, &r).unwrap();
        let check_msg = ElGamal::<C>::decrypt(&parameter, &sk, &cipher).unwrap();

        assert_eq!(msg, check_msg);
    }
}
