use elliptic_curve::{
    AffinePoint, CurveArithmetic, CurveGroup, FieldBytesSize, Group, Scalar, SecretKey,
    group::ff::PrimeField,
    ops::Reduce,
    sec1::{self, FromSec1Point, ToSec1Point},
};

use hybrid_array::Array;
use ml_dsa::{Generate, Keypair, MlDsaParams, SigningKey};

use getrandom::SysRng;

use crypto_bigint::{BitOps, Encoding};

use crate::Error;

pub(crate) fn bytes2scalar<C: CurveArithmetic>(mut bytes: &[u8]) -> Scalar<C> {
    // Compute number of bytes in `n` (curve order)
    let n_bits = C::ORDER.bits();
    let n_bytes = n_bits.div_ceil(8) as usize;
    if bytes.len() > n_bytes {
        bytes = &bytes[..n_bytes];
    }

    <Scalar<C> as Reduce<C::Uint>>::reduce(&C::Uint::from_be_slice_truncated(bytes, n_bits))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature<C, M>
where
    C: CurveArithmetic,
    M: MlDsaParams,
{
    s: Array<u8, M::SignatureSize>,
    x: Array<u8, C::FieldBytesSize>,
}

impl<C, M> TryFrom<&[u8]> for Signature<C, M>
where
    C: CurveArithmetic,
    M: MlDsaParams,
{
    type Error = Error;

    fn try_from(buffer: &[u8]) -> Result<Signature<C, M>, Error> {
        let mut s: Array<u8, M::SignatureSize> = Default::default();
        let mut x: Array<u8, C::FieldBytesSize> = Default::default();

        let expected = s.len() + x.len();
        if buffer.len() != expected {
            return Err(Error::InvalidLength {
                expected,
                actual: buffer.len(),
            });
        }

        let (s_buf, x_buf) = buffer.split_at(s.len());
        s.copy_from_slice(s_buf);
        x.copy_from_slice(x_buf);

        Ok(Signature { s, x })
    }
}

impl<C, M> Signature<C, M>
where
    C: CurveArithmetic,
    M: MlDsaParams,
{
    pub fn extract_c(&self) -> Array<u8, M::Lambda> {
        let (c, _, _) = M::split_sig(&self.s);
        c.clone()
    }
}

pub struct Key<C, M>
where
    C: CurveArithmetic,
    M: MlDsaParams,
{
    pub ec_key: elliptic_curve::SecretKey<C>,
    pub mldsa_key: ml_dsa::SigningKey<M>,
}

impl<C, M> Key<C, M>
where
    C: CurveArithmetic,
    M: MlDsaParams,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub fn keygen() -> Result<Self, Error> {
        let ec_key = SecretKey::<C>::try_generate()?;
        let mldsa_key = SigningKey::<M>::try_generate()?;

        Ok(Self { ec_key, mldsa_key })
    }

    fn serialize_commitment(&self, nonce: AffinePoint<C>) -> Vec<u8> {
        let ec_pk = self.ec_key.public_key();
        let enc_pk = ec_pk.to_sec1_point(true);
        let enc_nonce = nonce.to_sec1_point(true);

        let commit_len = enc_pk.len() * 2;

        let mut commit: Vec<u8> = vec![0; commit_len];
        commit[..enc_pk.len()].copy_from_slice(enc_nonce.as_bytes());
        commit[enc_pk.len()..].copy_from_slice(enc_pk.as_bytes());

        commit
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature<C, M>, Error> {
        // r = RandomScalar()
        let r = C::Scalar::try_generate()?;

        // R = r*G
        let nonce = C::ProjectivePoint::mul_by_generator(&r).to_affine();

        // ctx = R || P
        let ctx = self.serialize_commitment(nonce);

        let mldsa_sig = self
            .mldsa_key
            .expanded_key()
            .sign_randomized(msg, &ctx, &mut SysRng)
            .map_err(|_| Error::Signing)?;

        let mldsa_encoded = mldsa_sig.encode();

        let (c_bytes, _, _) = M::split_sig(&mldsa_encoded);
        let c = bytes2scalar::<C>(c_bytes);

        // x = r + sk1 * c
        let sk = C::Scalar::from(self.ec_key.to_nonzero_scalar());
        let x: Scalar<C> = r + sk * c;

        Ok(Signature {
            s: mldsa_encoded,
            x: x.to_repr(),
        })
    }

    pub fn verify(&self, msg: &[u8], sig: Signature<C, M>) -> bool {
        let c = bytes2scalar::<C>(&sig.extract_c());
        let x = bytes2scalar::<C>(&sig.x);

        let vk1 = self.ec_key.public_key().to_projective();

        // R = x*G - c*vk1
        let nonce = C::ProjectivePoint::mul_by_generator(&x) - c * vk1;

        // ctx = R || P
        let ctx = self.serialize_commitment(nonce.to_affine());

        // A malformed ML-DSA encoding is an invalid signature
        let Some(sig_dec) = ml_dsa::Signature::<M>::decode(&sig.s) else {
            return false;
        };

        self.mldsa_key
            .verifying_key()
            .verify_with_context(msg, &ctx, &sig_dec)
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
    use p256::NistP256;
    use p384::NistP384;
    use p521::NistP521;

    use super::*;

    fn basic<C, M>()
    where
        C: CurveArithmetic,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        M: MlDsaParams,
    {
        let key = Key::<C, M>::keygen().unwrap();
        let msg = b"hello";
        let sig = key.sign(msg).unwrap();
        assert!(key.verify(msg, sig));
    }

    fn fail<C, M>()
    where
        C: CurveArithmetic,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        M: MlDsaParams,
    {
        let key = Key::<C, M>::keygen().unwrap();
        let msg = b"hello";
        let sig = key.sign(msg).unwrap();

        // Fault in the ML-DSA part
        let mut sig_fault = sig.clone();
        sig_fault.s[1] = !sig_fault.s[1];
        assert_eq!(key.verify(msg, sig_fault), false);

        // Fault in the EC-Schnorr part
        sig_fault = sig.clone();
        sig_fault.x[1] = !sig_fault.x[1];
        assert_eq!(key.verify(msg, sig_fault), false);
    }

    fn malformed<C, M>()
    where
        C: CurveArithmetic,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
        M: MlDsaParams,
    {
        let key = Key::<C, M>::keygen().unwrap();
        let msg = b"hello";
        let mut sig_fault = key.sign(msg).unwrap();

        // Invalid hint encoding: ML-DSA decoding fails
        let n = sig_fault.s.len();
        sig_fault.s[n - 1] = 0xff;
        assert_eq!(key.verify(msg, sig_fault), false);

        // Truncated buffer
        let buffer = [0u8; 100];
        assert!(matches!(
            Signature::<C, M>::try_from(&buffer[..]),
            Err(Error::InvalidLength { actual: 100, .. })
        ));
    }

    // ML-DSA-87 keys are large (~178 KB) and unoptimized builds copy them
    // several times on the stack, which overflows the default 2 MB test thread.
    fn with_big_stack(f: fn()) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn basic_tests() {
        with_big_stack(|| {
            basic::<NistP256, MlDsa44>();
            basic::<NistP384, MlDsa65>();
            basic::<NistP521, MlDsa87>();
        });
    }

    #[test]
    fn fail_tests() {
        with_big_stack(|| {
            fail::<NistP256, MlDsa44>();
            fail::<NistP384, MlDsa65>();
            fail::<NistP521, MlDsa87>();
        });
    }

    #[test]
    fn malformed_tests() {
        with_big_stack(|| {
            malformed::<NistP256, MlDsa44>();
            malformed::<NistP384, MlDsa65>();
            malformed::<NistP521, MlDsa87>();
        });
    }
}
