use curve25519_dalek::{EdwardsPoint, digest::Digest, scalar::Scalar};
use ml_dsa::{Generate, Keypair, MlDsa44, SigningKey};

use getrandom::SysRng;

use hybrid_array::{Array, typenum::U64};

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use sha2::Sha512;

use crate::Error;

pub struct Signature {
    s: [u8; 2420],
    x: [u8; 32],
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(buffer: &[u8]) -> Result<Signature, Error> {
        let mut r = Signature {
            s: [0u8; 2420],
            x: [0u8; 32],
        };

        let expected = r.s.len() + r.x.len();
        if buffer.len() != expected {
            return Err(Error::InvalidLength {
                expected,
                actual: buffer.len(),
            });
        }

        let (s_buf, x_buf) = buffer.split_at(r.s.len());
        r.s.copy_from_slice(s_buf);
        r.x.copy_from_slice(x_buf);
        Ok(r)
    }
}

impl Signature {
    pub fn extract_c(&self) -> [u8; 32] {
        let mut c = [0u8; 32];
        let (c_buf, _) = self.s.split_at(32);
        c.copy_from_slice(c_buf);
        c
    }
}

pub struct Key {
    pub eddsa_key: ed25519_dalek::SigningKey,
    pub mldsa_key: ml_dsa::SigningKey<MlDsa44>,
    trace: [u8; 64],
    sk_hash: [u8; 32],
}

impl Key {
    pub fn keygen() -> Result<Self, Error> {
        let mut eddsa_secret = ed25519_dalek::SecretKey::default();
        getrandom::fill(&mut eddsa_secret)?;
        let eddsa_key = ed25519_dalek::SigningKey::from_bytes(&eddsa_secret);
        let mldsa_key = SigningKey::<MlDsa44>::try_generate()?;

        // tr = H(vk1 || vk2)
        let mut hasher = Shake256::default();
        hasher.update(eddsa_key.verifying_key().as_bytes());
        hasher.update(&mldsa_key.verifying_key().encode());
        let mut reader = hasher.finalize_xof();
        let mut trace = [0u8; 64];
        reader.read(&mut trace);

        // sk_h = H(sk1)
        let hash = Sha512::default()
            .chain_update(eddsa_key.to_bytes())
            .finalize();
        let mut sk_hash: [u8; 32] = [0u8; 32];
        sk_hash.copy_from_slice(&hash[32..64]);

        Ok(Self {
            eddsa_key,
            mldsa_key,
            trace,
            sk_hash,
        })
    }

    fn compute_mu(&self, nonce: EdwardsPoint, msg: &[u8]) -> Array<u8, U64> {
        // mu = H(tr || R || msg)
        let mut h = Shake256::default();
        h.update(&self.trace);
        h.update(&nonce.compress().to_bytes());
        h.update(msg);
        let mut reader = h.finalize_xof();
        let mut mu: Array<u8, U64> = Array::default();
        reader.read(&mut mu);

        mu
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        // r = SHA512(sk_h || msg)
        let hash = Sha512::default()
            .chain_update(self.sk_hash)
            .chain_update(msg)
            .finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&hash);
        let r = Scalar::from_bytes_mod_order_wide(&digest);

        // R = r*G
        let nonce = EdwardsPoint::mul_base(&r);

        // mu = H(tr || R || msg)
        let mu = self.compute_mu(nonce, msg);

        let mldsa_sig = self
            .mldsa_key
            .expanded_key()
            .sign_mu_randomized(&mu, &mut SysRng)
            .map_err(|_| Error::Signing)?;
        let mldsa_encoded = mldsa_sig.encode();

        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&mldsa_encoded[..32]);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // x = r + sk1 * c
        let x = r + self.eddsa_key.to_scalar() * c;

        Ok(Signature {
            s: mldsa_encoded.into(),
            x: x.to_bytes(),
        })
    }

    pub fn verify(&self, msg: &[u8], sig: Signature) -> bool {
        let c = Scalar::from_bytes_mod_order(sig.extract_c());
        let x = Scalar::from_bytes_mod_order(sig.x);

        let vk1 = self.eddsa_key.verifying_key().to_edwards();

        // R = x*G - c*vk1
        let nonce = EdwardsPoint::mul_base(&x) - c * vk1;

        // mu = H(tr || R || mg)
        let mu = self.compute_mu(nonce, msg);

        // A malformed ML-DSA encoding is an invalid signature
        let Some(sig_dec) = ml_dsa::Signature::<MlDsa44>::decode(&sig.s.into()) else {
            return false;
        };

        self.mldsa_key.verifying_key().verify_mu(&mu, &sig_dec)
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, Signature};
    use crate::Error;

    #[test]
    fn basic() {
        let key = Key::keygen().unwrap();
        let msg = b"hello";
        let sig = key.sign(msg).unwrap();
        assert!(key.verify(msg, sig));
    }

    #[test]
    fn fail() {
        let key = Key::keygen().unwrap();
        let msg = b"hello";
        let mut sig_fault = key.sign(msg).unwrap();
        sig_fault.s[1] = !sig_fault.s[1];
        assert_eq!(key.verify(msg, sig_fault), false);
    }

    #[test]
    fn invalid_length() {
        let buffer = [0u8; 100];
        assert_eq!(
            Signature::try_from(&buffer[..]).err(),
            Some(Error::InvalidLength {
                expected: 2452,
                actual: 100
            })
        );
    }

    #[test]
    fn malformed_encoding() {
        let key = Key::keygen().unwrap();
        let msg = b"hello";
        let mut sig_fault = key.sign(msg).unwrap();

        // Invalid hint encoding: ML-DSA decoding fails
        let n = sig_fault.s.len();
        sig_fault.s[n - 1] = 0xff;
        assert_eq!(key.verify(msg, sig_fault), false);
    }
}
