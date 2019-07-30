//! This module provides an API for the Diffie Hellman key exchange and an
//! implementation over the x25519 curve

use crate::traits::*;
use std::convert::TryFrom;
use core::array::*;
use crypto_derive::{SilentDebug, SilentDisplay};
use failure::prelude::*;
use x25519_dalek;

/// TODO: move traits to the right file (possibly traits.rs)

/// Key interfaces for Diffie-Hellman key exchange protocol build on top
/// of the key APIs in traits.rs

/// A type family for DH private key material
pub trait EphemeralKey:
    PrivateKey<PublicKeyMaterial = <Self as EphemeralKey>::DHPublicKeyMaterial> +
    Uniform //+ Drop
{
    /// The associated PublicKey type
    type DHPublicKeyMaterial: PublicKey<PrivateKeyMaterial = Self>;
    /// The associated SharedKey type
    type DHSharedKeyMaterial; // This type should be bounded by the right
    // traits for ecryption and signing 
    /// Generates a SharedKey using a peer PublicKey
    fn dh(self, public_key: &Self::DHPublicKeyMaterial) -> Self::DHSharedKeyMaterial;
}

/// x25519 Implementation

/// The length of the DHPublicKey
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;


// Zoe: Is the wrapping in new data structures necessary? Can we just
// provide trait implementation for the dalek datatypes?

/// An x25519 ephemeral key
#[derive(SilentDisplay, SilentDebug)]
pub struct X25519EphemeralKey(pub (crate) x25519_dalek::EphemeralSecret);

/// An x25519 static key
#[derive(SilentDisplay, SilentDebug, Clone)]
pub struct X25519StaticKey(pub (crate) x25519_dalek::StaticSecret);

/// An x25519 public key
#[derive(Clone, Debug)]
pub struct X25519PublicKey(pub (crate) x25519_dalek::PublicKey);

/// An x25519 shared key
#[derive(SilentDisplay, SilentDebug)]
pub struct X25519SharedKey(pub (crate) x25519_dalek::SharedSecret);


/////////////////////////
// EphemeralKey Traits //
/////////////////////////

impl Uniform for X25519EphemeralKey {
    fn generate_for_testing<R>(rng: &mut R) -> Self
    where
        R: ::rand::SeedableRng + ::rand::RngCore + ::rand::CryptoRng,
    {
        X25519EphemeralKey(x25519_dalek::EphemeralSecret::new(rng))
    }
}

// impl Drop for X25519EphemeralKey {
//     fn drop(&mut self) {
//         drop(&self.0)
//     }
// }

impl PrivateKey for X25519EphemeralKey {
    type PublicKeyMaterial = X25519PublicKey;
}

impl EphemeralKey for X25519EphemeralKey {
    type DHPublicKeyMaterial = X25519PublicKey;
    type DHSharedKeyMaterial = X25519SharedKey;
    // Diffie-Hellman exchanfe
    fn dh(self, their_public:&X25519PublicKey) -> X25519SharedKey {
        let shared_secret = self.0.diffie_hellman(&their_public.0);
        X25519SharedKey(shared_secret)
    }
}

//////////////////////
// StaticKey Traits //
//////////////////////

impl Uniform for X25519StaticKey {
    fn generate_for_testing<R>(rng: &mut R) -> Self
    where
        R: ::rand::SeedableRng + ::rand::RngCore + ::rand::CryptoRng,
    {
        X25519StaticKey(x25519_dalek::StaticSecret::new(rng))
    }
}

impl Drop for X25519StaticKey {
    fn drop(&mut self) {
        drop(&self.0)
    }
}


impl TryFrom<&[u8]> for X25519StaticKey {
    type Error = CryptoMaterialError;
    fn try_from(bytes: &[u8]) -> std::result::Result<X25519StaticKey, CryptoMaterialError> {
         if bytes.len() != 32 {
             return Err(CryptoMaterialError::DeserializationError);
        }
        let mut bits = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(X25519StaticKey(x25519_dalek::StaticSecret::from(bits)))
    }
}

impl ValidKey for X25519StaticKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

//////////////////////
// PublicKey Traits //
//////////////////////

impl<'a> From<&'a X25519EphemeralKey> for X25519PublicKey {
    fn from(ephemeral: &'a X25519EphemeralKey) -> X25519PublicKey {
        X25519PublicKey(x25519_dalek::PublicKey::from(&ephemeral.0))
    }
}

impl<'a> From<&'a X25519StaticKey> for X25519PublicKey {
    fn from(ephemeral: &'a X25519StaticKey) -> X25519PublicKey {
        X25519PublicKey(x25519_dalek::PublicKey::from(&ephemeral.0))
    }
}


impl std::hash::Hash for X25519PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.0.as_bytes();
        state.write(encoded_pubkey);
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &X25519PublicKey) -> bool {
        *self.0.as_bytes() == *other.0.as_bytes()
    }
}

impl Eq for X25519PublicKey {}

impl PublicKey for X25519PublicKey {
    type PrivateKeyMaterial = X25519EphemeralKey;
    fn length() -> usize {
        X25519_PUBLIC_KEY_LENGTH
    }
}


//////////////////////
// SharedKey Traits //
//////////////////////

