use std::borrow::Borrow;
use std::ops::Deref;
use std::sync::Arc;

// Turn on blinding in the RSA crate
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, PublicKeyParts, PublicKey, Hash};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey, DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use ::sha2::{Digest, Sha256, Sha384, Sha512};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::*;
use crate::asymmetric_common::*;
use crate::error::*;
use crate::rand::SecureRandom;

const RAW_ENCODING_VERSION: u16 = 2;
const RAW_ENCODING_ALG_ID: u16 = 1;
const MIN_MODULUS_SIZE: u32 = 2048;
const MAX_MODULUS_SIZE: u32 = 4096;

#[derive(Debug, Clone)]
pub struct RsaSignatureSecretKey {
    pub alg: SignatureAlgorithm,
}

#[derive(Serialize, Deserialize, Zeroize)]
struct RsaSignatureKeyPairParts {
    version: u16,
    alg_id: u16,
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    //p: Vec<u8>,
    //q: Vec<u8>,
    primes: Vec<BigUint>,
    //dmp1: Vec<u8>,
    //dmq1: Vec<u8>,
    //iqmp: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RsaSignatureKeyPair {
    pub alg: SignatureAlgorithm,
    ctx: RsaPrivateKey,
}

fn modulus_bits(alg: SignatureAlgorithm) -> Result<u32, CryptoError> {
    let modulus_bits = match alg {
        SignatureAlgorithm::RSA_PKCS1_2048_SHA256
        | SignatureAlgorithm::RSA_PKCS1_2048_SHA384
        | SignatureAlgorithm::RSA_PKCS1_2048_SHA512
        | SignatureAlgorithm::RSA_PSS_2048_SHA256
        | SignatureAlgorithm::RSA_PSS_2048_SHA384
        | SignatureAlgorithm::RSA_PSS_2048_SHA512 => 2048,
        SignatureAlgorithm::RSA_PKCS1_3072_SHA384
        | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
        | SignatureAlgorithm::RSA_PSS_3072_SHA384
        | SignatureAlgorithm::RSA_PSS_3072_SHA512 => 3072,
        SignatureAlgorithm::RSA_PKCS1_4096_SHA512 | SignatureAlgorithm::RSA_PSS_4096_SHA512 => 4096,
        _ => bail!(CryptoError::UnsupportedAlgorithm),
    };
    Ok(modulus_bits)
}

impl RsaSignatureKeyPair {
    fn from_pkcs8(alg: SignatureAlgorithm, der: &[u8]) -> Result<Self, CryptoError> {
        ensure!(der.len() < 4096, CryptoError::InvalidKey);
        let ctx = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidKey)?;
        ctx.validate().map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &str) -> Result<Self, CryptoError> {
        ensure!(pem.len() < 4096, CryptoError::InvalidKey);
        let ctx = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn from_local(alg: SignatureAlgorithm, local: &[u8]) -> Result<Self, CryptoError> {
        ensure!(local.len() < 2048, CryptoError::InvalidKey);
        let parts: RsaSignatureKeyPairParts =
            bincode::deserialize(local).map_err(|_| CryptoError::InvalidKey)?;
        ensure!(
            parts.version == RAW_ENCODING_VERSION && parts.alg_id == RAW_ENCODING_ALG_ID,
            CryptoError::InvalidKey
        );
        let n = BigUint::from_bytes_be(&parts.n);
        let e = BigUint::from_bytes_be(&parts.e);
        let d = BigUint::from_bytes_be(&parts.d);
        let p = BigUint::from_bytes_be(&parts.p);
        let q = BigUint::from_bytes_be(&parts.q);
        /*let dmp1 = BigUint::from_bytes_be(&parts.dmp1);
        let dmq1 = BigUint::from_bytes_be(&parts.dmq1);
        let iqmp = BigUint::from_bytes_be(&parts.iqmp);*/
        let ctx = rsa::RsaPrivateKey::from_components(n, e, d, parts.primes);

        //let ctx: rsa_impl::Rsa<pkey::Private> =
        //    rsa_impl::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)
        //        .map_err(|_| CryptoError::InvalidKey)?;
        ctx.validate().map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn to_pkcs8(&self) -> Result<Vec<u8>, CryptoError> {
        self.ctx
            .private_key_to_der()
            .map_err(|_| CryptoError::InternalError)
    }

    fn to_pem(&self) -> Result<Vec<u8>, CryptoError> {
        self.ctx
            .private_key_to_pem()
            .map_err(|_| CryptoError::InternalError)
    }

    fn to_local(&self) -> Result<Vec<u8>, CryptoError> {
        let parts = RsaSignatureKeyPairParts {
            version: RAW_ENCODING_VERSION,
            alg_id: RAW_ENCODING_ALG_ID,
            n: self.ctx.n().to_bytes_be(),
            e: self.ctx.e().to_bytes_be(),
            d: self.ctx.d().to_bytes_be(),
            primes: self.ctx.primes().to_vec(),
            //p: self.ctx.primes().get(0)?.to_bytes_be(),
            //q: self.ctx.primes().get(1)?.to_bytes_be(),
            //dmp1: self.ctx.dmp1().ok_or(CryptoError::InternalError)?.to_vec(),
            //dmq1: self.ctx.dmq1().ok_or(CryptoError::InternalError)?.to_vec(),
            //iqmp: self.ctx.iqmp().ok_or(CryptoError::InternalError)?.to_vec(),
        };
        let local = bincode::serialize(&parts).map_err(|_| CryptoError::InternalError)?;
        Ok(local)
    }

    pub fn generate(
        alg: SignatureAlgorithm,
        _options: Option<SignatureOptions>,
    ) -> Result<Self, CryptoError> {
        let mut rng = rand_core::OsRng::default();
        let modulus_bits = modulus_bits(alg)?;
        let ctx = RsaPrivateKey::new(&mut rng, modulus_bits as usize).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<Self, CryptoError> {
        match alg.family() {
            SignatureAlgorithmFamily::RSA => {}
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let kp = match encoding {
            KeyPairEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded)?,
            KeyPairEncoding::Pem => Self::from_pem(alg, encoded.into())?,
            KeyPairEncoding::Local => Self::from_local(alg, encoded)?,
            _ => bail!(CryptoError::UnsupportedEncoding),
        };
        let modulus_size = kp.ctx.size();
        let min_modulus_bits = modulus_bits(alg)?;
        ensure!(
            (min_modulus_bits / 8..=MAX_MODULUS_SIZE / 8).contains(&modulus_size),
            CryptoError::InvalidKey
        );
        kp.ctx.check_key().map_err(|_| CryptoError::InvalidKey)?;
        Ok(kp)
    }

    pub fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoError> {
        match encoding {
            KeyPairEncoding::Pkcs8 => self.to_pkcs8(),
            KeyPairEncoding::Pem => self.to_pem(),
            KeyPairEncoding::Local => self.to_local(),
            _ => bail!(CryptoError::UnsupportedEncoding),
        }
    }

    pub fn public_key(&self) -> Result<RsaSignaturePublicKey, CryptoError> {
        Ok(RsaSignaturePublicKey { alg: self.alg, ctx: self.ctx.to_public_key() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaSignature {
    pub raw: Vec<u8>,
}

impl RsaSignature {
    pub fn new(raw: Vec<u8>) -> Self {
        RsaSignature { raw }
    }

    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoError> {
        let expected_len = (modulus_bits(alg)? / 8) as _;
        ensure!(raw.len() == expected_len, CryptoError::InvalidSignature);
        Ok(Self::new(raw.to_vec()))
    }
}

impl SignatureLike for RsaSignature {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

fn do_the_hash(hash: rsa::hash::Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::MD5 => {}
        Hash::SHA1 => {}
        Hash::SHA2_224 => sha2::Sha224::digest(data).to_vec(),
        Hash::SHA2_256 => {}
        Hash::SHA2_384 => {}
        Hash::SHA2_512 => {}
        Hash::SHA3_256 => {}
        Hash::SHA3_384 => {}
        Hash::SHA3_512 => {}
        Hash::MD5SHA1 => {}
        Hash::RIPEMD160 => {}
    }
}

fn padding_scheme(alg: SignatureAlgorithm) -> (rsa::padding::PaddingScheme, rsa::hash::Hash) {
    match alg {
        SignatureAlgorithm::RSA_PKCS1_2048_SHA256 => {
            (rsa::padding::PaddingScheme::PKCS1v15Sign {hash: Some(rsa::hash::Hash::SHA2_256)}, rsa::hash::Hash::SHA2_256 )
        }
        SignatureAlgorithm::RSA_PKCS1_2048_SHA384 | SignatureAlgorithm::RSA_PKCS1_3072_SHA384 => {
            (rsa_impl::Padding::PKCS1, rsa::hash::Hash::SHA2_384)
        }
        SignatureAlgorithm::RSA_PKCS1_2048_SHA512
        | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
        | SignatureAlgorithm::RSA_PKCS1_4096_SHA512 => {
            (rsa_impl::Padding::PKCS1, rsa::hash::Hash::SHA2_512)
        }

        SignatureAlgorithm::RSA_PSS_2048_SHA256 => {
            (rsa_impl::Padding::PKCS1, rsa::hash::Hash::SHA2_256)
        }
        SignatureAlgorithm::RSA_PSS_2048_SHA384 | SignatureAlgorithm::RSA_PSS_3072_SHA384 => (
            rsa_impl::Padding::PKCS1_PSS,
            rsa::hash::Hash::SHA2_384,
        ),
        SignatureAlgorithm::RSA_PSS_2048_SHA512
        | SignatureAlgorithm::RSA_PSS_3072_SHA512
        | SignatureAlgorithm::RSA_PSS_4096_SHA512 => (
            rsa_impl::Padding::PKCS1_PSS,
            rsa::hash::Hash::SHA2_512,
        ),
        _ => unreachable!(),
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum HashVariant {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl HashVariant {
    fn for_alg(alg: SignatureAlgorithm) -> Result<Self, CryptoError> {
        let h = match alg {
            SignatureAlgorithm::RSA_PKCS1_2048_SHA256 | SignatureAlgorithm::RSA_PSS_2048_SHA256 => {
                HashVariant::Sha256(Sha256::new())
            }
            SignatureAlgorithm::RSA_PKCS1_2048_SHA384
            | SignatureAlgorithm::RSA_PKCS1_3072_SHA384
            | SignatureAlgorithm::RSA_PSS_2048_SHA384
            | SignatureAlgorithm::RSA_PSS_3072_SHA384 => HashVariant::Sha384(Sha384::new()),
            SignatureAlgorithm::RSA_PKCS1_2048_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
            | SignatureAlgorithm::RSA_PKCS1_4096_SHA512
            | SignatureAlgorithm::RSA_PSS_2048_SHA512
            | SignatureAlgorithm::RSA_PSS_3072_SHA512
            | SignatureAlgorithm::RSA_PSS_4096_SHA512 => HashVariant::Sha512(Sha512::new()),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        Ok(h)
    }
}

pub struct RsaSignatureState<'z> {
    ctx: Box<pkey::PKey<pkey::Private>>,
    signer: boring::sign::Signer<'z>,
}

impl<'z> RsaSignatureState<'z> {
    pub fn new(kp: RsaSignatureKeyPair) -> Self {
        let ctx = Box::new(pkey::PKey::from_rsa(kp.ctx).unwrap());
        let (padding_alg, padding_hash) = padding_scheme(kp.alg);
        let pkr: *const pkey::PKeyRef<pkey::Private> = ctx.as_ref().borrow();
        let mut signer = boring::sign::Signer::new(padding_hash, unsafe { &*pkr }).unwrap();
        signer
            .set_rsa_padding(padding_alg)
            .expect("Unexpected padding");
        RsaSignatureState { ctx, signer }
    }
}

impl<'z> SignatureStateLike for RsaSignatureState<'z> {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        self.signer
            .update(input)
            .map_err(|_| CryptoError::InternalError)?;
        Ok(())
    }

    fn sign(&mut self) -> Result<Signature, CryptoError> {
        let signature = self
            .signer
            .sign_to_vec()
            .map_err(|_| CryptoError::InternalError)?;
        let signature = RsaSignature::new(signature);
        Ok(Signature::new(Box::new(signature)))
    }
}

pub struct RsaSignatureVerificationState<'z> {
    ctx: RsaPublicKey,
    data: Vec<u8>,
    alg: SignatureAlgorithm,
    //ctx: Box<pkey::PKey<pkey::Public>>,
    //verifier: boring::sign::Verifier<'z>,
}

impl<'z> RsaSignatureVerificationState<'z> {
    pub fn new(pk: RsaSignaturePublicKey) -> Self {
        /*
        let ctx = Box::new(pkey::PKey::from_rsa(pk.ctx).unwrap());
        let (padding_alg, padding_hash) = padding_scheme(pk.alg);
        let pkr: *const pkey::PKeyRef<pkey::Public> = ctx.as_ref().borrow();
        let mut verifier = boring::sign::Verifier::new(padding_hash, unsafe { &*pkr }).unwrap();
        verifier
            .set_rsa_padding(padding_alg)
            .expect("Unexpected padding");

        RsaSignatureVerificationState { ctx, verifier }*/
        RsaSignatureVerificationState {
            ctx: pk.ctx,
            data: Vec::new(),
            alg: pk.alg,
        }
    }
}

impl<'t> SignatureVerificationStateLike for RsaSignatureVerificationState<'t> {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        let mut temp = input.to_vec();
        self.data.append(&mut temp);
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> Result<(), CryptoError> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<RsaSignature>()
            .ok_or(CryptoError::InvalidSignature)?;

        let (padding, hash) = padding_scheme(self.alg);
        self.ctx.verify(padding, hash, signature.raw.as_slice()).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
struct RsaSignaturePublicKeyParts {
    version: u16,
    alg_id: u16,
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RsaSignaturePublicKey {
    pub alg: SignatureAlgorithm,
    ctx: RsaPublicKey,
}

impl RsaSignaturePublicKey {
    fn from_pkcs8(alg: SignatureAlgorithm, der: &[u8]) -> Result<Self, CryptoError> {
        ensure!(der.len() < 4096, CryptoError::InvalidKey);
        let ctx = RsaPublicKey::from_public_key_der(der).map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> Result<Self, CryptoError> {
        ensure!(pem.len() < 4096, CryptoError::InvalidKey);
        let ctx = RsaPublicKey::from_public_key_pem(pem.into()).or_else(|_| RsaPublicKey::from_pkcs1_pem(pem.into())).map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn from_local(alg: SignatureAlgorithm, local: &[u8]) -> Result<Self, CryptoError> {
        ensure!(local.len() < 1024, CryptoError::InvalidKey);
        let parts: RsaSignaturePublicKeyParts =
            bincode::deserialize(local).map_err(|_| CryptoError::InvalidKey)?;
        ensure!(
            parts.version == RAW_ENCODING_VERSION && parts.alg_id == RAW_ENCODING_ALG_ID,
            CryptoError::InvalidKey
        );
        let n = BigUint::from_bytes_be(&parts.n);
        let e = BigUint::from_bytes_be(&parts.e);
        let ctx = RsaPublicKey::new(n, e).map_err(|_| CryptoError::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn to_pkcs8(&self) -> Result<Vec<u8>, CryptoError> {
        self.ctx
            .public_key_to_der()
            .map_err(|_| CryptoError::InternalError)
    }

    fn to_pem(&self) -> Result<Vec<u8>, CryptoError> {
        self.ctx
            .public_key_to_pem()
            .map_err(|_| CryptoError::InternalError)
    }

    fn to_local(&self) -> Result<Vec<u8>, CryptoError> {
        let parts = RsaSignaturePublicKeyParts {
            version: RAW_ENCODING_VERSION,
            alg_id: RAW_ENCODING_ALG_ID,
            n: self.ctx.n().to_bytes_be(),
            e: self.ctx.e().to_bytes_be(),
        };
        let local = bincode::serialize(&parts).map_err(|_| CryptoError::InternalError)?;
        Ok(local)
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublicKeyEncoding,
    ) -> Result<Self, CryptoError> {
        let pk = match encoding {
            PublicKeyEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded)?,
            PublicKeyEncoding::Pem => Self::from_pem(alg, encoded)?,
            PublicKeyEncoding::Local => Self::from_local(alg, encoded)?,
            _ => bail!(CryptoError::UnsupportedEncoding),
        };
        let modulus_size = pk.ctx.size();
        let min_modulus_bits = modulus_bits(alg)?;
        ensure!(
            modulus_size >= min_modulus_bits / 8 && modulus_size <= MAX_MODULUS_SIZE / 8,
            CryptoError::InvalidKey
        );
        Ok(pk)
    }

    pub fn export(&self, encoding: PublicKeyEncoding) -> Result<Vec<u8>, CryptoError> {
        match encoding {
            PublicKeyEncoding::Pkcs8 => self.to_pkcs8(),
            PublicKeyEncoding::Pem => self.to_pem(),
            PublicKeyEncoding::Local => self.to_local(),
            _ => bail!(CryptoError::UnsupportedEncoding),
        }
    }
}
