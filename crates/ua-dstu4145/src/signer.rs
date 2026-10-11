use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::{CryptoRng, OsRng, RngCore};
use ua_gf2m::{CurvePoint, FieldElement};
use ua_gost::Gost34311;

use crate::encoding::{
    bit_length, decode_signature, encode_signature, field_element_to_integer, hash_message, hash_message_with_hasher,
    hash_to_field_element,
};
use crate::{DomainParameters, KeyPair, Presignature, SigningError};

/// L_D is a multiple of 16 (5.7).
const SIGNATURE_BITS_GRANULE: u32 = 16;
const BYTE_BITS: u32 = 8;

/// The DSTU 4145-2002 signature: key generation (9), presignature (11), signing (12) and verification (13).
///
/// `sign_message` / `verify_message` hash with GOST 34.311 (6.2); `sign_hash` / `verify_hash` take a ready hash
/// code H(T) as bytes, most significant first (see [`hash_to_field_element`]), so any hash function fits. Randomness
/// comes from `R`: the OS generator by default, or e.g. the generator of Appendix А.
pub struct Signer<R = OsRng> {
    parameters: DomainParameters,
    rng: R,
}

impl Signer<OsRng> {
    /// The signer with the operating system's generator.
    pub fn new(parameters: &DomainParameters) -> Self {
        Self::with_rng(parameters, OsRng)
    }
}

impl<R: RngCore + CryptoRng> Signer<R> {
    /// The signer with the given generator.
    pub fn with_rng(parameters: &DomainParameters, rng: R) -> Self {
        Self {
            parameters: parameters.clone(),
            rng,
        }
    }

    /// The domain parameters the signer works with.
    pub fn parameters(&self) -> &DomainParameters {
        &self.parameters
    }

    /// 9.1–9.2: a random private key d ≠ 0 and the public key Q = −dP.
    pub fn generate_key_pair(&mut self) -> KeyPair {
        loop {
            let d = self.parameters.generate_integer(&mut self.rng);
            if let Ok(public_key) = self.calculate_public_key(&d) {
                return KeyPair {
                    private_key: d,
                    public_key,
                };
            }
        }
    }

    /// 9.2: Q = −dP.
    pub fn calculate_public_key(&self, private_key: &BigUint) -> Result<CurvePoint, SigningError> {
        self.require_private_key_in_range(private_key)?;
        let p = self.parameters.base_point();
        Ok(self
            .parameters
            .curve()
            .multiply_fixed_length(p, private_key, self.parameters.n())
            .negate())
    }

    /// Section 11: a random e and F_e = x(eP) ≠ 0.
    pub fn generate_presignature(&mut self) -> Presignature {
        loop {
            let e = self.parameters.generate_integer(&mut self.rng);
            if e.is_zero() {
                continue;
            }
            if let Some(presignature) = self.calculate_presignature(&e) {
                return presignature;
            }
        }
    }

    /// Section 11 for a given e (tests, precomputation); absent when x(eP) = 0 and another e must be taken.
    ///
    /// # Panics
    ///
    /// When e is not in 0 < e < n.
    pub fn calculate_presignature(&self, e: &BigUint) -> Option<Presignature> {
        assert!(!e.is_zero() && e < self.parameters.n(), "0 < e < n is required");
        let p = self.parameters.base_point();
        let r = self.parameters.curve().multiply_fixed_length(p, e, self.parameters.n());
        let x = r.x().filter(|x| !x.is_zero())?;
        Some(Presignature {
            e: e.clone(),
            fe: x.clone(),
        })
    }

    /// Section 12: signs a hash code; the signature D has the shortest admissible length.
    pub fn sign_hash(&mut self, private_key: &BigUint, hash: &[u8]) -> Result<Vec<u8>, SigningError> {
        let signature_bits = self.parameters.minimum_signature_bits();
        self.sign_hash_with_length(private_key, hash, signature_bits)
    }

    /// Section 12: signs a hash code into a signature D of `signature_bits` bits (big-endian bytes).
    pub fn sign_hash_with_length(
        &mut self,
        private_key: &BigUint,
        hash: &[u8],
        signature_bits: u32,
    ) -> Result<Vec<u8>, SigningError> {
        self.require_valid_signature_length(signature_bits)?;
        self.require_private_key_in_range(private_key)?;
        let h = self.hash_element(hash)?;
        loop {
            let presignature = self.generate_presignature();
            if let Some((r, s)) = self.sign(private_key, &h, &presignature)? {
                return match encode_signature(&r, &s, signature_bits) {
                    Ok(signature) => Ok(signature),
                    Err(error) => unreachable!("r, s < n fit into L_D / 2 ≥ L(n) bits: {error}"),
                };
            }
        }
    }

    /// Steps 9–13 of section 12 with an explicit presignature: (r, s), or absent when r = 0 or s = 0 and another
    /// presignature must be taken.
    pub fn sign(
        &self,
        private_key: &BigUint,
        h: &FieldElement,
        presignature: &Presignature,
    ) -> Result<Option<(BigUint, BigUint)>, SigningError> {
        self.require_private_key_in_range(private_key)?;
        let n = self.parameters.n();
        let one = self.parameters.field().one();
        let h = if h.is_zero() { &one } else { h }; // step 7

        let y = h * &presignature.fe; // step 9
        let r = field_element_to_integer(&y, n); // step 10
        if r.is_zero() {
            return Ok(None);
        }
        let s = (&presignature.e + private_key * &r) % n; // step 12
        if s.is_zero() {
            return Ok(None);
        }
        Ok(Some((r, s)))
    }

    /// Section 12 with the GOST 34.311 hash and the default DKE.
    pub fn sign_message(&mut self, private_key: &BigUint, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.sign_hash(private_key, &hash_message(message))
    }

    /// Section 12 with the GOST 34.311 hash of `hasher` (e.g. one built from a certificate's DKE).
    pub fn sign_message_with_hasher(
        &mut self,
        private_key: &BigUint,
        message: &[u8],
        hasher: &mut Gost34311,
    ) -> Result<Vec<u8>, SigningError> {
        self.sign_hash(private_key, &hash_message_with_hasher(message, hasher))
    }

    /// Section 13: whether D (big-endian bytes) is a signature of the hash code under the public key.
    pub fn verify_hash(&self, public_key: &CurvePoint, hash: &[u8], signature: &[u8]) -> bool {
        let signature_bits = signature.len() as u64 * u64::from(BYTE_BITS);
        if signature_bits % u64::from(SIGNATURE_BITS_GRANULE) != 0
            || signature_bits < 2 * bit_length(self.parameters.n())
        {
            return false; // step 3
        }
        let (Ok((r, s)), Ok(h)) = (decode_signature(signature), self.hash_element(hash)) else {
            return false;
        };
        self.verify(public_key, &h, &r, &s)
    }

    /// Section 13 with the GOST 34.311 hash and the default DKE.
    pub fn verify_message(&self, public_key: &CurvePoint, message: &[u8], signature: &[u8]) -> bool {
        self.verify_hash(public_key, &hash_message(message), signature)
    }

    /// Section 13 with the GOST 34.311 hash of `hasher`.
    pub fn verify_message_with_hasher(
        &self,
        public_key: &CurvePoint,
        message: &[u8],
        signature: &[u8],
        hasher: &mut Gost34311,
    ) -> bool {
        self.verify_hash(public_key, &hash_message_with_hasher(message, hasher), signature)
    }

    /// Steps 10–15 of section 13.
    ///
    /// The public key is not checked here (10.1 allows skipping it for safely stored keys); a key obtained by
    /// decompression may lie outside the subgroup of order n, so check untrusted keys with
    /// [`DomainParameters::validate_public_key`].
    pub fn verify(&self, public_key: &CurvePoint, h: &FieldElement, r: &BigUint, s: &BigUint) -> bool {
        let curve = self.parameters.curve();
        let n = self.parameters.n();
        if curve != public_key.curve() || public_key.is_infinity() {
            return false;
        }
        if r.is_zero() || r >= n || s.is_zero() || s >= n {
            return false;
        }
        let one = self.parameters.field().one();
        let h = if h.is_zero() { &one } else { h };

        let r_point = &curve.multiply(self.parameters.base_point(), s) + &curve.multiply(public_key, r); // sP + rQ
        let Some(x) = r_point.x() else {
            return false;
        };
        field_element_to_integer(&(h * x), n) == *r
    }

    fn hash_element(&self, hash: &[u8]) -> Result<FieldElement, SigningError> {
        if hash.is_empty() {
            return Err(SigningError::EmptyHash);
        }
        let h = hash_to_field_element(hash, self.parameters.field());
        Ok(if h.is_zero() { self.parameters.field().one() } else { h })
    }

    fn require_private_key_in_range(&self, d: &BigUint) -> Result<(), SigningError> {
        if d.is_zero() || d >= self.parameters.n() {
            return Err(SigningError::PrivateKeyOutOfRange);
        }
        Ok(())
    }

    fn require_valid_signature_length(&self, bits: u32) -> Result<(), SigningError> {
        if bits % SIGNATURE_BITS_GRANULE != 0 || u64::from(bits) < 2 * bit_length(self.parameters.n()) {
            return Err(SigningError::InvalidSignatureLength(bits));
        }
        Ok(())
    }
}
