//! Inert packaging of constellation discovery metadata as immutable RVF context.
//!
//! This adapter checks the version, native URI and discovery safety projection.
//! It is not the complete `manifest.ruv` JSON Schema validator. Validate the
//! complete public schema in the constellation publisher before calling it.
//! Neither a manifest nor the resulting RVF grants authority, proves a claimed
//! capability, registers an alias, or executes code. Visibility is an untrusted
//! publisher declaration; public release needs a separate disclosure review.

use crate::{CompiledContextArtifact, ContextCompileRequest, RvfContextCompiler};
use crate::{ServiceError, ServiceResult};
use rvm_context::{Collection, Revision, RuvUri, SubjectKind};
use rvm_rvf::sha256;
use serde::Deserialize;

/// Maximum input size accepted by this metadata adapter, before JSON parsing.
pub const MAX_DISCOVERY_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryProjection {
    schema_version: String,
    id: String,
    repository: RepositoryProjection,
    safety: SafetyProjection,
}

#[derive(Deserialize)]
struct RepositoryProjection {
    url: String,
    visibility: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SafetyProjection {
    discovery_only: bool,
    execution_requires_authorization: bool,
}

/// An exact-byte metadata artifact, with a separately checked logical name.
///
/// Its URI is not published or registered. `content_digest` hashes the input
/// JSON bytes, while the artifact identity hashes the complete RVF container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDiscoveryManifest {
    uri: RuvUri,
    content_digest: Revision,
    artifact: CompiledContextArtifact,
}

impl CompiledDiscoveryManifest {
    /// Native canonical logical name, without a revision or progressive view.
    #[must_use]
    pub const fn uri(&self) -> &RuvUri {
        &self.uri
    }

    /// SHA-256 of the original manifest bytes, including formatting.
    #[must_use]
    pub const fn content_digest(&self) -> Revision {
        self.content_digest
    }

    /// Self-verified, non-executable RVF context artifact.
    #[must_use]
    pub const fn artifact(&self) -> &CompiledContextArtifact {
        &self.artifact
    }
}

/// Package an already schema-validated public discovery manifest as RVF data.
///
/// Keeps the exact input bytes as the authoritative `content` view. It does
/// not fetch references, register names, resolve capabilities, or execute.
/// Extra metadata fields are intentionally preserved without interpretation.
///
/// # Errors
/// Refuses empty or oversized input, malformed JSON, duplicate projected
/// fields, unsupported schema versions, invalid or out-of-scope native URIs,
/// private visibility declarations, missing discovery safety flags, and RVF
/// compiler verification failures.
pub fn compile_discovery_manifest(bytes: &[u8]) -> ServiceResult<CompiledDiscoveryManifest> {
    if bytes.is_empty() || bytes.len() > MAX_DISCOVERY_MANIFEST_BYTES {
        return Err(ServiceError::CorruptState("discovery manifest size invalid"));
    }
    let projection: DiscoveryProjection = serde_json::from_slice(bytes)
        .map_err(|_| ServiceError::CorruptState("discovery manifest JSON invalid"))?;
    if projection.schema_version != "0.1"
        || projection.repository.visibility != "public"
        || !projection.safety.discovery_only
        || !projection.safety.execution_requires_authorization
    {
        return Err(ServiceError::CorruptState(
            "unsupported discovery manifest version or safety declaration",
        ));
    }
    let uri: RuvUri = projection
        .id
        .parse()
        .map_err(|_| ServiceError::CorruptState("discovery manifest URI invalid"))?;
    let repo = projection
        .repository
        .url
        .strip_prefix("https://github.com/ruvnet/")
        .filter(|name| {
            !name.is_empty()
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                })
        })
        .ok_or(ServiceError::CorruptState("discovery repository URL invalid"))?;
    let subject_id = repo.to_ascii_lowercase().replace(['.', '_'], "-");
    if uri.authority().as_str() != "ruvnet"
        || uri.tenant().as_str() != "constellation"
        || uri.subject().kind() != SubjectKind::Service
        || uri.subject().id().as_str() != subject_id
        || uri.collection() != Collection::Resources
        || uri.path().len() != 1
        || uri.path()[0].as_str() != "manifest.ruv"
        || uri.revision().is_some()
        || uri.view().is_some()
    {
        return Err(ServiceError::CorruptState(
            "discovery manifest URI outside constellation scope",
        ));
    }
    let artifact = RvfContextCompiler::compile(ContextCompileRequest::data(bytes.to_vec()))?;
    Ok(CompiledDiscoveryManifest {
        uri,
        content_digest: Revision::from_bytes(sha256(bytes)),
        artifact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_context::{ProfileTrust, ProgressiveView, VerifiedContextProfile};

    fn projection() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": "0.1",
            "id": "ruv://ruvnet/constellation/service/rvm/resources/manifest.ruv",
            "repository": { "url": "https://github.com/ruvnet/rvm", "visibility": "public" },
            "safety": { "discoveryOnly": true, "executionRequiresAuthorization": true }
        })
    }

    #[test]
    fn packages_exact_bytes_deterministically_with_native_uri() {
        // The adapter deliberately validates a projection, not the full schema.
        let bytes = serde_json::to_vec_pretty(&projection()).unwrap();
        let compiled = compile_discovery_manifest(&bytes).unwrap();
        let repeated = compile_discovery_manifest(&bytes).unwrap();
        assert_eq!(compiled, repeated);
        assert_eq!(compiled.content_digest(), Revision::from_bytes(sha256(&bytes)));
        assert_eq!(compiled.uri().subject().id().as_str(), "rvm");
        let artifact = compiled.artifact();
        let profile = VerifiedContextProfile::from_rvf(
            artifact.rvf(),
            artifact.identity(),
            ProfileTrust::PinnedIdentity,
            &[],
        )
        .unwrap();
        assert_eq!(
            profile.payload(artifact.rvf(), ProgressiveView::Content).unwrap(),
            bytes
        );
        let compact = serde_json::to_vec(&projection()).unwrap();
        assert_ne!(
            compile_discovery_manifest(&compact).unwrap().artifact().identity(),
            artifact.identity()
        );
    }

    #[test]
    fn rejects_unsafe_and_noncanonical_metadata() {
        for uri in [
            "ruv://ruvnet/rvm",
            "ruv://ruvnet/constellation/service/with_dot/resources/manifest.ruv",
            "ruv://ruvnet/constellation/service/RVM/resources/manifest.ruv",
            "ruv://other/constellation/service/rvm/resources/manifest.ruv",
            "ruv://ruvnet/private/service/rvm/resources/manifest.ruv",
            "ruv://ruvnet/constellation/agent/rvm/resources/manifest.ruv",
            "ruv://ruvnet/constellation/service/rvm/skills/manifest.ruv",
            "ruv://ruvnet/constellation/service/rvm/resources/other.json",
            "ruv://ruvnet/constellation/service/rvm/resources/manifest.ruv?view=content",
            "ruv://ruvnet/constellation/service/rvm/resources/../manifest.ruv",
            "ruv://ruvnet/constellation/service/rvm/resources/%6danifest.ruv",
        ] {
            let mut value = projection();
            value["id"] = uri.into();
            assert!(compile_discovery_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for (field, value) in [("schemaVersion", "1.0"), ("schemaVersion", "0.1.0")] {
            let mut manifest = projection();
            manifest[field] = value.into();
            assert!(compile_discovery_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err());
        }
        for visibility in ["private", "internal"] {
            let mut value = projection();
            value["repository"]["visibility"] = visibility.into();
            assert!(compile_discovery_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for flag in ["discoveryOnly", "executionRequiresAuthorization"] {
            let mut value = projection();
            value["safety"][flag] = false.into();
            assert!(compile_discovery_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn refuses_duplicate_guard_fields_and_bounded_input() {
        let bytes = serde_json::to_string(&projection()).unwrap();
        let duplicate = bytes.replacen("{", "{\"schemaVersion\":\"0.1\",", 1);
        assert!(compile_discovery_manifest(duplicate.as_bytes()).is_err());
        assert!(compile_discovery_manifest(b"{}").is_err());
        assert!(compile_discovery_manifest(b"not JSON").is_err());
        assert!(compile_discovery_manifest(b"").is_err());
        assert!(compile_discovery_manifest(&vec![b' '; MAX_DISCOVERY_MANIFEST_BYTES + 1]).is_err());
    }
}
