//! Epoch receipt encoding, decoding, and verification.
//!
//! # Receipt signatures are a keyed MAC, not a public signature
//!
//! Witness receipts are signed with HMAC-SHA256, which is symmetric.
//! Verifying a receipt requires the **same 32-byte key that signed it**. A caller holding that key can forge a receipt exactly as easily as it
//! can check one, so verification here is an integrity check against
//! corruption, truncation, and accidental mismatch — it is not third-party
//! verifiable evidence, and a receipt checked in JavaScript proves nothing to
//! anyone who did not already trust the key holder.
//!
//! The keyless checks are the ones that carry weight across a trust boundary:
//! [`crate::ContextRuntime::verify_witness_chain`] and the record digests,
//! which are pure functions of the record bytes.
//!
//! Receipts are signed through `rvm_proof::WitnessSigner` (a distinct trait
//! from the same-named one in `rvm-witness`). Its implementations include
//! `HmacSha256WitnessSigner`, used here, and a feature-gated
//! `Ed25519WitnessSigner` that this build does not enable — `ed25519` is not a
//! default feature of `rvm-proof`, and its constructor takes a signing seed
//! rather than a bare public key, so it would not offer verify-only checking
//! either.
//!
//! The host supplies the key. This module deliberately does not expose
//! `default_signer`, `with_default_key`, `derive_witness_key`, or
//! `dev_measurement`: a well-known or derivable default key is
//! indistinguishable from no key at all.

use crate::error::{argument_error, receipt_error};
use rvm_context::receipt::{
    ContextEpochReceipt, SignedContextEpochReceipt, CONTEXT_RECEIPT_ENCODED_SIZE,
    CONTEXT_RECEIPT_VERSION,
};
use rvm_proof::HmacSha256WitnessSigner;
use wasm_bindgen::prelude::*;

/// The encoded size of a signed receipt in bytes.
#[wasm_bindgen(js_name = receiptEncodedSize)]
#[must_use]
pub fn receipt_encoded_size() -> usize {
    CONTEXT_RECEIPT_ENCODED_SIZE
}

/// The receipt format version this binding implements.
#[wasm_bindgen(js_name = receiptVersion)]
#[must_use]
pub fn receipt_version() -> u16 {
    CONTEXT_RECEIPT_VERSION
}

pub(crate) fn signer_from_key(key: &[u8]) -> Result<HmacSha256WitnessSigner, JsValue> {
    let key: [u8; 32] = key.try_into().map_err(|_| {
        argument_error(
            "InvalidKeyLength",
            "the witness HMAC key must be exactly 32 bytes",
        )
    })?;
    Ok(HmacSha256WitnessSigner::new(key))
}

/// A signed epoch receipt.
#[wasm_bindgen]
#[derive(Clone)]
pub struct SignedReceipt {
    inner: SignedContextEpochReceipt,
}

impl SignedReceipt {
    pub(crate) fn from_inner(inner: SignedContextEpochReceipt) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl SignedReceipt {
    /// Decodes a receipt from its canonical byte encoding.
    ///
    /// # Errors
    ///
    /// Throws `ContextReceiptError` when the bytes are the wrong length,
    /// version, or shape.
    pub fn decode(bytes: &[u8]) -> Result<SignedReceipt, JsValue> {
        SignedContextEpochReceipt::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(receipt_error)
    }

    /// Encodes the receipt canonically.
    #[wasm_bindgen(js_name = toBytes)]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// The receipt's own identity digest.
    #[wasm_bindgen(getter, js_name = receiptId)]
    #[must_use]
    pub fn receipt_id(&self) -> Vec<u8> {
        self.inner.receipt_id().to_vec()
    }

    /// The identity of the key that signed this receipt.
    #[wasm_bindgen(getter, js_name = signerId)]
    #[must_use]
    pub fn signer_id(&self) -> Vec<u8> {
        self.inner.signer_id().to_vec()
    }

    /// The raw signature bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature(&self) -> Vec<u8> {
        self.inner.signature().to_vec()
    }

    /// The epoch this receipt seals.
    #[wasm_bindgen(getter, js_name = epochId)]
    #[must_use]
    pub fn epoch_id(&self) -> u64 {
        self.receipt().epoch_id()
    }

    /// The first witness sequence covered.
    #[wasm_bindgen(getter, js_name = firstSequence)]
    #[must_use]
    pub fn first_sequence(&self) -> u64 {
        self.receipt().first_sequence()
    }

    /// The last witness sequence covered.
    #[wasm_bindgen(getter, js_name = lastSequence)]
    #[must_use]
    pub fn last_sequence(&self) -> u64 {
        self.receipt().last_sequence()
    }

    /// How many witness records the epoch covers.
    #[wasm_bindgen(getter, js_name = recordCount)]
    #[must_use]
    pub fn record_count(&self) -> u32 {
        self.receipt().record_count()
    }

    /// The logical timestamp the epoch started at.
    #[wasm_bindgen(getter, js_name = startedNs)]
    #[must_use]
    pub fn started_ns(&self) -> u64 {
        self.receipt().started_ns()
    }

    /// The logical timestamp the epoch ended at.
    #[wasm_bindgen(getter, js_name = endedNs)]
    #[must_use]
    pub fn ended_ns(&self) -> u64 {
        self.receipt().ended_ns()
    }

    /// The digest of the previous receipt in the chain.
    #[wasm_bindgen(getter, js_name = previousReceipt)]
    #[must_use]
    pub fn previous_receipt(&self) -> Vec<u8> {
        self.receipt().previous_receipt().to_vec()
    }

    /// The witness root committed by this receipt.
    #[wasm_bindgen(getter, js_name = witnessRoot)]
    #[must_use]
    pub fn witness_root(&self) -> Vec<u8> {
        self.receipt().witness_root().to_vec()
    }

    /// The namespace root committed by this receipt.
    #[wasm_bindgen(getter, js_name = namespaceRoot)]
    #[must_use]
    pub fn namespace_root(&self) -> Vec<u8> {
        self.receipt().namespace_root().to_vec()
    }

    /// The policy hash committed by this receipt.
    #[wasm_bindgen(getter, js_name = policyHash)]
    #[must_use]
    pub fn policy_hash(&self) -> Vec<u8> {
        self.receipt().policy_hash().to_vec()
    }

    /// Checks the receipt's HMAC against `key`, and that it is a valid genesis
    /// receipt.
    ///
    /// `key` must be the same 32 bytes that signed the receipt. See the module
    /// documentation: possession of this key is possession of signing power.
    ///
    /// # Errors
    ///
    /// Throws `ContextReceiptError` when the signature does not match or the
    /// receipt is not a well-formed genesis.
    /// Throws `ContextArgumentError` when `key` is not 32 bytes.
    #[wasm_bindgen(js_name = verifyGenesis)]
    pub fn verify_genesis(&self, key: &[u8]) -> Result<(), JsValue> {
        let signer = signer_from_key(key)?;
        let verified = self.inner.verify(&signer).map_err(receipt_error)?;
        verified.verify_genesis().map_err(receipt_error)
    }

    /// Checks the receipt's HMAC against `key`, and that it validly succeeds
    /// `previous`.
    ///
    /// Both receipts are checked against the same key, since a continuity link
    /// between receipts signed by different keys establishes nothing.
    ///
    /// # Errors
    ///
    /// Throws `ContextReceiptError` when either signature does not match or
    /// the continuity link to `previous` is broken.
    /// Throws `ContextArgumentError` when `key` is not 32 bytes.
    #[wasm_bindgen(js_name = verifySuccessor)]
    pub fn verify_successor(&self, previous: &SignedReceipt, key: &[u8]) -> Result<(), JsValue> {
        let signer = signer_from_key(key)?;
        let previous_verified = previous.inner.verify(&signer).map_err(receipt_error)?;
        let verified = self.inner.verify(&signer).map_err(receipt_error)?;
        verified
            .verify_successor(&previous_verified)
            .map_err(receipt_error)
    }

    /// Checks only the receipt's HMAC against `key`.
    ///
    /// # Errors
    ///
    /// Throws `ContextReceiptError` when the signature does not match.
    /// Throws `ContextArgumentError` when `key` is not 32 bytes.
    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(&self, key: &[u8]) -> Result<(), JsValue> {
        let signer = signer_from_key(key)?;
        self.inner
            .verify(&signer)
            .map(|_| ())
            .map_err(receipt_error)
    }
}

impl SignedReceipt {
    fn receipt(&self) -> &ContextEpochReceipt {
        self.inner.receipt()
    }
}
