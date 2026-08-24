//! Strict, canonical parsing and formatting for the `ruv://` namespace.
//!
//! A `ruv://` URI is a name, not an authority token. This module deliberately
//! accepts only one spelling for every name so that policy scopes, witness
//! records, signatures, and caches cannot disagree about URI equivalence.

use alloc::{string::String, vec::Vec};
use core::{fmt, str::FromStr};

const SCHEME: &str = "ruv://";
const MAX_URI_BYTES: usize = 2_048;
const MAX_AUTHORITY_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;
const MAX_IDENTIFIER_BYTES: usize = 63;
const MAX_PATH_SEGMENT_BYTES: usize = 128;
const MAX_PATH_SEGMENTS: usize = 32;
const MAX_PATH_BYTES: usize = 1_024;

/// A failure to parse or construct a canonical `ruv://` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    /// The complete URI exceeds 2,048 bytes.
    UriTooLong,
    /// The URI contains a non-ASCII byte.
    NonAscii,
    /// The scheme is not exactly lowercase `ruv://`.
    InvalidScheme,
    /// Percent encoding is forbidden by the v1 canonical contract.
    PercentEncodingNotAllowed,
    /// URI fragments are forbidden.
    FragmentNotAllowed,
    /// User information or credentials appear in the authority.
    CredentialsNotAllowed,
    /// An authority port is present.
    PortNotAllowed,
    /// The DNS authority is empty, malformed, noncanonical, or too long.
    InvalidAuthority,
    /// The tenant identifier is not a canonical lowercase slug.
    InvalidTenant,
    /// The subject kind is not one of the registered lowercase values.
    InvalidSubjectKind,
    /// The subject identifier is not a canonical lowercase slug.
    InvalidSubjectId,
    /// The collection is not one of the registered lowercase values.
    InvalidCollection,
    /// A required hierarchy component is missing.
    MissingComponent,
    /// A hierarchy component between slashes is empty.
    EmptyPathSegment,
    /// The hierarchical path has a trailing slash.
    TrailingSlash,
    /// A path contains the `.` or `..` traversal segment.
    DotSegment,
    /// A path segment contains a forbidden character or exceeds 128 bytes.
    InvalidPathSegment,
    /// More than 32 optional path segments were supplied.
    TooManyPathSegments,
    /// The optional path exceeds 1,024 bytes including separators.
    PathTooLong,
    /// The query is empty or structurally malformed.
    InvalidQuery,
    /// The query contains a key other than `rev` or `view`.
    UnknownQueryKey,
    /// A query key occurs more than once.
    DuplicateQueryKey,
    /// Query keys are not in canonical `rev` then `view` order.
    QueryOrder,
    /// A revision is not `sha256:` followed by 64 lowercase hexadecimal digits.
    InvalidRevision,
    /// A progressive view is not `abstract`, `overview`, or `content`.
    InvalidView,
    /// Conversion to [`PinnedRuvUri`] was requested without a revision.
    RevisionRequired,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UriTooLong => "ruv URI exceeds 2048 bytes",
            Self::NonAscii => "ruv URI must contain ASCII only",
            Self::InvalidScheme => "scheme must be exactly ruv://",
            Self::PercentEncodingNotAllowed => "percent encoding is not allowed",
            Self::FragmentNotAllowed => "URI fragments are not allowed",
            Self::CredentialsNotAllowed => "authority credentials are not allowed",
            Self::PortNotAllowed => "authority ports are not allowed",
            Self::InvalidAuthority => "invalid canonical DNS authority",
            Self::InvalidTenant => "invalid canonical tenant slug",
            Self::InvalidSubjectKind => "invalid subject kind",
            Self::InvalidSubjectId => "invalid canonical subject slug",
            Self::InvalidCollection => "invalid collection",
            Self::MissingComponent => "required URI component is missing",
            Self::EmptyPathSegment => "empty path segment is not allowed",
            Self::TrailingSlash => "trailing slash is not allowed",
            Self::DotSegment => "dot path segments are not allowed",
            Self::InvalidPathSegment => "invalid canonical path segment",
            Self::TooManyPathSegments => "too many path segments",
            Self::PathTooLong => "path exceeds 1024 bytes",
            Self::InvalidQuery => "invalid canonical query",
            Self::UnknownQueryKey => "unknown query key",
            Self::DuplicateQueryKey => "duplicate query key",
            Self::QueryOrder => "query keys are not in canonical order",
            Self::InvalidRevision => "invalid SHA-256 revision",
            Self::InvalidView => "invalid progressive view",
            Self::RevisionRequired => "a pinned ruv URI requires a revision",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UriError {}

fn reject_forbidden_octets(value: &str) -> Result<(), UriError> {
    // One pass collecting three verdicts. The verdicts are ranked after the
    // scan rather than during it, so which error a caller sees never depends on
    // which forbidden byte happens to appear first.
    let mut non_ascii = false;
    let mut percent = false;
    let mut fragment = false;
    for &byte in value.as_bytes() {
        non_ascii |= !byte.is_ascii();
        percent |= byte == b'%';
        fragment |= byte == b'#';
    }
    if non_ascii {
        return Err(UriError::NonAscii);
    }
    if percent {
        return Err(UriError::PercentEncodingNotAllowed);
    }
    if fragment {
        return Err(UriError::FragmentNotAllowed);
    }
    Ok(())
}

fn is_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && is_ascii_lowercase_or_digit(bytes[0])
        && is_ascii_lowercase_or_digit(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|byte| is_ascii_lowercase_or_digit(*byte) || *byte == b'-')
}

fn is_ascii_lowercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/// A canonical lowercase DNS authority without credentials or a port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority(String);

impl Authority {
    /// Validates and constructs an authority.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] when `value` is not canonical lowercase DNS text
    /// or contains credentials, a port, percent encoding, or non-ASCII bytes.
    pub fn new(value: &str) -> Result<Self, UriError> {
        reject_forbidden_octets(value)?;
        Self::new_prevalidated(value)
    }

    /// Constructs without re-scanning for globally forbidden octets.
    ///
    /// [`RuvUri::from_str`] validates the whole input with
    /// [`reject_forbidden_octets`] before it splits on `/`, so every component it
    /// derives is already known to be ASCII and free of `%` and `#`. Re-scanning
    /// each component repeats that work once per component. The public `new`
    /// constructors keep the scan, because their callers arrive with text nobody
    /// has checked.
    fn new_prevalidated(value: &str) -> Result<Self, UriError> {
        if value.as_bytes().contains(&b'@') {
            return Err(UriError::CredentialsNotAllowed);
        }
        if value.as_bytes().contains(&b':') {
            return Err(UriError::PortNotAllowed);
        }
        if value.is_empty() || value.len() > MAX_AUTHORITY_BYTES {
            return Err(UriError::InvalidAuthority);
        }
        for label in value.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_DNS_LABEL_BYTES
                || !is_ascii_lowercase_or_digit(bytes[0])
                || !is_ascii_lowercase_or_digit(bytes[bytes.len() - 1])
                || !bytes
                    .iter()
                    .all(|byte| is_ascii_lowercase_or_digit(*byte) || *byte == b'-')
            {
                return Err(UriError::InvalidAuthority);
            }
        }
        Ok(Self(String::from(value)))
    }

    /// Returns the canonical authority text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Authority {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Authority {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Authority {
    type Error = UriError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A canonical tenant slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Validates and constructs a tenant identifier.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] when `value` is not a lowercase slug of at most
    /// 63 bytes or contains a globally forbidden URI byte.
    pub fn new(value: &str) -> Result<Self, UriError> {
        reject_forbidden_octets(value)?;
        Self::new_prevalidated(value)
    }

    /// Constructs without re-scanning for globally forbidden octets.
    ///
    /// [`RuvUri::from_str`] validates the whole input with
    /// [`reject_forbidden_octets`] before it splits on `/`, so every component it
    /// derives is already known to be ASCII and free of `%` and `#`. Re-scanning
    /// each component repeats that work once per component. The public `new`
    /// constructors keep the scan, because their callers arrive with text nobody
    /// has checked.
    fn new_prevalidated(value: &str) -> Result<Self, UriError> {
        if !is_slug(value) {
            return Err(UriError::InvalidTenant);
        }
        Ok(Self(String::from(value)))
    }

    /// Returns the canonical tenant slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TenantId {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for TenantId {
    type Error = UriError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A canonical subject slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId(String);

impl SubjectId {
    /// Validates and constructs a subject identifier.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] when `value` is not a lowercase slug of at most
    /// 63 bytes or contains a globally forbidden URI byte.
    pub fn new(value: &str) -> Result<Self, UriError> {
        reject_forbidden_octets(value)?;
        Self::new_prevalidated(value)
    }

    /// Constructs without re-scanning for globally forbidden octets.
    ///
    /// [`RuvUri::from_str`] validates the whole input with
    /// [`reject_forbidden_octets`] before it splits on `/`, so every component it
    /// derives is already known to be ASCII and free of `%` and `#`. Re-scanning
    /// each component repeats that work once per component. The public `new`
    /// constructors keep the scan, because their callers arrive with text nobody
    /// has checked.
    fn new_prevalidated(value: &str) -> Result<Self, UriError> {
        if !is_slug(value) {
            return Err(UriError::InvalidSubjectId);
        }
        Ok(Self(String::from(value)))
    }

    /// Returns the canonical subject slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SubjectId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubjectId {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for SubjectId {
    type Error = UriError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// The principal category named by a context URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubjectKind {
    /// An autonomous or user-directed agent.
    Agent,
    /// A human user.
    User,
    /// A service principal.
    Service,
    /// A team principal.
    Team,
}

impl SubjectKind {
    /// Returns the registered lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
            Self::Service => "service",
            Self::Team => "team",
        }
    }
}

impl fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubjectKind {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent" => Ok(Self::Agent),
            "user" => Ok(Self::User),
            "service" => Ok(Self::Service),
            "team" => Ok(Self::Team),
            _ => Err(UriError::InvalidSubjectKind),
        }
    }
}

/// A typed subject identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject {
    kind: SubjectKind,
    id: SubjectId,
}

impl Subject {
    /// Constructs a subject from already validated components.
    #[must_use]
    pub const fn new(kind: SubjectKind, id: SubjectId) -> Self {
        Self { kind, id }
    }

    /// Returns the subject category.
    #[must_use]
    pub const fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// Returns the subject identifier.
    #[must_use]
    pub const fn id(&self) -> &SubjectId {
        &self.id
    }
}

/// A top-level context collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Collection {
    /// Durable or episodic agent memory.
    Memory,
    /// Readable context resources.
    Resources,
    /// Discoverable or executable skill artifacts.
    Skills,
}

impl Collection {
    /// Returns the registered lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Resources => "resources",
            Self::Skills => "skills",
        }
    }
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Collection {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "memory" => Ok(Self::Memory),
            "resources" => Ok(Self::Resources),
            "skills" => Ok(Self::Skills),
            _ => Err(UriError::InvalidCollection),
        }
    }
}

/// One case-sensitive ASCII-unreserved segment below a collection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathSegment(String);

impl PathSegment {
    /// Validates and constructs a path segment.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] when `value` is empty, a dot segment, longer than
    /// 128 bytes, non-ASCII, or contains a character outside the unreserved
    /// set.
    pub fn new(value: &str) -> Result<Self, UriError> {
        reject_forbidden_octets(value)?;
        Self::new_prevalidated(value)
    }

    /// Constructs without re-scanning for globally forbidden octets.
    ///
    /// [`RuvUri::from_str`] validates the whole input with
    /// [`reject_forbidden_octets`] before it splits on `/`, so every component it
    /// derives is already known to be ASCII and free of `%` and `#`. Re-scanning
    /// each component repeats that work once per component. The public `new`
    /// constructors keep the scan, because their callers arrive with text nobody
    /// has checked.
    fn new_prevalidated(value: &str) -> Result<Self, UriError> {
        if value.is_empty() {
            return Err(UriError::EmptyPathSegment);
        }
        if value == "." || value == ".." {
            return Err(UriError::DotSegment);
        }
        if value.len() > MAX_PATH_SEGMENT_BYTES
            || !value.as_bytes().iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return Err(UriError::InvalidPathSegment);
        }
        Ok(Self(String::from(value)))
    }

    /// Returns the exact case-sensitive segment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PathSegment {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PathSegment {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for PathSegment {
    type Error = UriError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A whole-container SHA-256 RVF identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision([u8; 32]);

impl Revision {
    /// Constructs a SHA-256 revision from its digest bytes.
    #[must_use]
    pub const fn sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Constructs a revision from a SHA-256 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::sha256(bytes)
    }

    /// Returns the raw SHA-256 digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0_u8; 71];
        encoded[..7].copy_from_slice(b"sha256:");
        for (index, byte) in self.0.iter().copied().enumerate() {
            encoded[7 + index * 2] = HEX[usize::from(byte >> 4)];
            encoded[8 + index * 2] = HEX[usize::from(byte & 0x0f)];
        }
        let text = core::str::from_utf8(&encoded).map_err(|_| fmt::Error)?;
        f.write_str(text)
    }
}

impl FromStr for Revision {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or(UriError::InvalidRevision)?;
        if hex.len() != 64
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(UriError::InvalidRevision);
        }
        let mut digest = [0_u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            let offset = index * 2;
            *byte =
                (hex_nibble(hex.as_bytes()[offset]) << 4) | hex_nibble(hex.as_bytes()[offset + 1]);
        }
        Ok(Self(digest))
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// A progressively more detailed view of a context object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgressiveView {
    /// A compact L0 abstract.
    Abstract,
    /// An L1 overview.
    Overview,
    /// Full L2 content.
    Content,
}

impl ProgressiveView {
    /// Returns the registered lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Abstract => "abstract",
            Self::Overview => "overview",
            Self::Content => "content",
        }
    }
}

impl fmt::Display for ProgressiveView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProgressiveView {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "abstract" => Ok(Self::Abstract),
            "overview" => Ok(Self::Overview),
            "content" => Ok(Self::Content),
            _ => Err(UriError::InvalidView),
        }
    }
}

/// A validated canonical `ruv://` URI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuvUri {
    authority: Authority,
    tenant: TenantId,
    subject: Subject,
    collection: Collection,
    path: Vec<PathSegment>,
    revision: Option<Revision>,
    view: Option<ProgressiveView>,
}

impl RuvUri {
    /// Parses a URI while requiring its input to already be canonical.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] for every noncanonical spelling, malformed
    /// component, forbidden construct, or exceeded resource limit.
    pub fn parse(value: &str) -> Result<Self, UriError> {
        value.parse()
    }

    /// Starts a builder from validated required components.
    #[must_use]
    pub fn builder(
        authority: Authority,
        tenant: TenantId,
        subject: Subject,
        collection: Collection,
    ) -> RuvUriBuilder {
        RuvUriBuilder::new(authority, tenant, subject, collection)
    }

    /// Returns the DNS authority.
    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Returns the tenant identifier.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the typed subject.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Returns the top-level collection.
    #[must_use]
    pub const fn collection(&self) -> Collection {
        self.collection
    }

    /// Returns optional path segments below the collection.
    #[must_use]
    pub fn path(&self) -> &[PathSegment] {
        &self.path
    }

    /// Returns the immutable RVF revision when this name is pinned.
    #[must_use]
    pub const fn revision(&self) -> Option<Revision> {
        self.revision
    }

    /// Returns the requested progressive view.
    #[must_use]
    pub const fn view(&self) -> Option<ProgressiveView> {
        self.view
    }

    /// Reports whether this URI includes an immutable revision.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        self.revision.is_some()
    }

    /// Returns a pinned copy of this URI.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::UriTooLong`] if adding the revision would exceed
    /// the complete URI byte limit.
    pub fn with_revision(mut self, revision: Revision) -> Result<PinnedRuvUri, UriError> {
        self.revision = Some(revision);
        validate_complete(&self)?;
        Ok(PinnedRuvUri {
            uri: self,
            revision,
        })
    }

    /// Returns a copy with the requested progressive view.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::UriTooLong`] if adding the view would exceed the
    /// complete URI byte limit.
    pub fn with_view(mut self, view: ProgressiveView) -> Result<Self, UriError> {
        self.view = Some(view);
        validate_complete(&self)?;
        Ok(self)
    }

    fn optional_path_bytes(&self) -> usize {
        self.path
            .iter()
            .map(|segment| segment.as_str().len())
            .sum::<usize>()
            + self.path.len().saturating_sub(1)
    }

    fn canonical_len(&self) -> usize {
        let mut length = SCHEME.len()
            + self.authority.as_str().len()
            + 4
            + self.tenant.as_str().len()
            + self.subject.kind().as_str().len()
            + self.subject.id().as_str().len()
            + self.collection.as_str().len();
        length += self
            .path
            .iter()
            .map(|segment| 1 + segment.as_str().len())
            .sum::<usize>();
        if self.revision.is_some() {
            length += 1 + 4 + 7 + 64;
        }
        if let Some(view) = self.view {
            length += 1 + 5 + view.as_str().len();
        }
        length
    }
}

fn validate_complete(uri: &RuvUri) -> Result<(), UriError> {
    if uri.path.len() > MAX_PATH_SEGMENTS {
        return Err(UriError::TooManyPathSegments);
    }
    if uri.optional_path_bytes() > MAX_PATH_BYTES {
        return Err(UriError::PathTooLong);
    }
    if uri.canonical_len() > MAX_URI_BYTES {
        return Err(UriError::UriTooLong);
    }
    Ok(())
}

impl FromStr for RuvUri {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_URI_BYTES {
            return Err(UriError::UriTooLong);
        }
        reject_forbidden_octets(value)?;
        let after_scheme = value.strip_prefix(SCHEME).ok_or(UriError::InvalidScheme)?;
        let (hierarchy, query) = match after_scheme.split_once('?') {
            Some((hierarchy, query)) => (hierarchy, Some(query)),
            None => (after_scheme, None),
        };
        if hierarchy.ends_with('/') {
            return Err(UriError::TrailingSlash);
        }

        let mut components = [""; 5 + MAX_PATH_SEGMENTS];
        let mut component_count = 0_usize;
        let mut has_empty_component = false;
        for component in hierarchy.split('/') {
            has_empty_component |= component.is_empty();
            if component_count < components.len() {
                components[component_count] = component;
            }
            component_count += 1;
        }
        if component_count < 5 {
            return Err(UriError::MissingComponent);
        }
        if has_empty_component {
            return Err(UriError::EmptyPathSegment);
        }

        // reject_forbidden_octets ran over the whole input above, so the
        // components carved out of it need no second scan.
        let authority = Authority::new_prevalidated(components[0])?;
        let tenant = TenantId::new_prevalidated(components[1])?;
        let subject_kind = components[2].parse()?;
        let subject_id = SubjectId::new_prevalidated(components[3])?;
        let collection = components[4].parse()?;
        let path_count = component_count - 5;
        if path_count > MAX_PATH_SEGMENTS {
            return Err(UriError::TooManyPathSegments);
        }
        let path_parts = &components[5..component_count];
        let path_bytes =
            path_parts.iter().map(|part| part.len()).sum::<usize>() + path_count.saturating_sub(1);
        if path_bytes > MAX_PATH_BYTES {
            return Err(UriError::PathTooLong);
        }
        let path = path_parts
            .iter()
            .map(|part| PathSegment::new_prevalidated(part))
            .collect::<Result<Vec<_>, _>>()?;
        let (revision, view) = parse_query(query)?;

        let uri = Self {
            authority,
            tenant,
            subject: Subject::new(subject_kind, subject_id),
            collection,
            path,
            revision,
            view,
        };
        validate_complete(&uri)?;
        Ok(uri)
    }
}

fn parse_query(
    query: Option<&str>,
) -> Result<(Option<Revision>, Option<ProgressiveView>), UriError> {
    let Some(query) = query else {
        return Ok((None, None));
    };
    if query.is_empty() {
        return Err(UriError::InvalidQuery);
    }

    let mut entries = query.split('&');
    let first = entries.next().ok_or(UriError::InvalidQuery)?;
    let second = entries.next();
    if entries.next().is_some() || first.is_empty() || second == Some("") {
        return Err(UriError::InvalidQuery);
    }
    let mut revision = None;
    let mut view = None;
    let mut saw_view = false;

    for entry in [Some(first), second].into_iter().flatten() {
        let (key, value) = entry.split_once('=').ok_or(UriError::InvalidQuery)?;
        if key.is_empty() || value.is_empty() || value.as_bytes().contains(&b'=') {
            return Err(UriError::InvalidQuery);
        }
        match key {
            "rev" => {
                if revision.is_some() {
                    return Err(UriError::DuplicateQueryKey);
                }
                if saw_view {
                    return Err(UriError::QueryOrder);
                }
                revision = Some(value.parse()?);
            }
            "view" => {
                if view.is_some() {
                    return Err(UriError::DuplicateQueryKey);
                }
                saw_view = true;
                view = Some(value.parse()?);
            }
            _ => return Err(UriError::UnknownQueryKey),
        }
    }
    Ok((revision, view))
}

impl fmt::Display for RuvUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}/{}/{}/{}/{}",
            self.authority,
            self.tenant,
            self.subject.kind(),
            self.subject.id(),
            self.collection
        )?;
        for segment in &self.path {
            write!(f, "/{segment}")?;
        }
        if let Some(revision) = self.revision {
            write!(f, "?rev={revision}")?;
        }
        if let Some(view) = self.view {
            if self.revision.is_some() {
                write!(f, "&view={view}")?;
            } else {
                write!(f, "?view={view}")?;
            }
        }
        Ok(())
    }
}

impl TryFrom<&str> for RuvUri {
    type Error = UriError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A `ruv://` URI guaranteed to contain an immutable RVF revision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedRuvUri {
    uri: RuvUri,
    revision: Revision,
}

impl PinnedRuvUri {
    /// Returns the underlying validated URI.
    #[must_use]
    pub const fn as_uri(&self) -> &RuvUri {
        &self.uri
    }

    /// Returns the required immutable revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Consumes the wrapper and returns the underlying URI.
    #[must_use]
    pub fn into_uri(self) -> RuvUri {
        self.uri
    }
}

impl TryFrom<RuvUri> for PinnedRuvUri {
    type Error = UriError;

    fn try_from(uri: RuvUri) -> Result<Self, Self::Error> {
        let revision = uri.revision.ok_or(UriError::RevisionRequired)?;
        Ok(Self { uri, revision })
    }
}

impl From<PinnedRuvUri> for RuvUri {
    fn from(uri: PinnedRuvUri) -> Self {
        uri.into_uri()
    }
}

impl FromStr for PinnedRuvUri {
    type Err = UriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(RuvUri::parse(value)?)
    }
}

impl fmt::Display for PinnedRuvUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.uri.fmt(f)
    }
}

/// Builder for a validated canonical `ruv://` URI.
#[derive(Debug, Clone)]
pub struct RuvUriBuilder {
    authority: Authority,
    tenant: TenantId,
    subject: Subject,
    collection: Collection,
    path: Vec<PathSegment>,
    revision: Option<Revision>,
    view: Option<ProgressiveView>,
}

impl RuvUriBuilder {
    /// Starts a builder from validated required components.
    #[must_use]
    pub const fn new(
        authority: Authority,
        tenant: TenantId,
        subject: Subject,
        collection: Collection,
    ) -> Self {
        Self {
            authority,
            tenant,
            subject,
            collection,
            path: Vec::new(),
            revision: None,
            view: None,
        }
    }

    /// Appends one validated path segment.
    #[must_use]
    pub fn path_segment(mut self, segment: PathSegment) -> Self {
        self.path.push(segment);
        self
    }

    /// Replaces the optional path with validated segments.
    #[must_use]
    pub fn path(mut self, path: Vec<PathSegment>) -> Self {
        self.path = path;
        self
    }

    /// Pins the name to an immutable RVF revision.
    #[must_use]
    pub const fn revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    /// Selects a progressive context view.
    #[must_use]
    pub const fn view(mut self, view: ProgressiveView) -> Self {
        self.view = Some(view);
        self
    }

    /// Validates aggregate limits and constructs the URI.
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] if the optional path or complete URI exceeds its
    /// aggregate limit.
    pub fn build(self) -> Result<RuvUri, UriError> {
        let uri = RuvUri {
            authority: self.authority,
            tenant: self.tenant,
            subject: self.subject,
            collection: self.collection,
            path: self.path,
            revision: self.revision,
            view: self.view,
        };
        validate_complete(&uri)?;
        Ok(uri)
    }

    /// Validates aggregate limits and constructs a pinned URI.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::RevisionRequired`] if no revision was supplied, or
    /// a resource-limit error if an aggregate URI limit is exceeded.
    pub fn build_pinned(self) -> Result<PinnedRuvUri, UriError> {
        PinnedRuvUri::try_from(self.build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};
    use proptest::prelude::*;

    const ZERO_REVISION: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn minimal_uri_round_trips() {
        let text = "ruv://context.example/acme/agent/researcher/memory";
        let uri = RuvUri::parse(text).unwrap();
        assert_eq!(uri.to_string(), text);
        assert_eq!(uri.authority().as_str(), "context.example");
        assert_eq!(uri.tenant().as_str(), "acme");
        assert_eq!(uri.subject().kind(), SubjectKind::Agent);
        assert_eq!(uri.subject().id().as_str(), "researcher");
        assert_eq!(uri.collection(), Collection::Memory);
        assert!(uri.path().is_empty());
        assert!(!uri.is_pinned());
    }

    #[test]
    fn full_uri_round_trips_and_preserves_path_case() {
        let text = format!(
            "ruv://context.example/acme/team/core/resources/Specs/API_v1?rev={ZERO_REVISION}&view=overview"
        );
        let uri = RuvUri::parse(&text).unwrap();
        assert_eq!(uri.to_string(), text);
        assert_eq!(uri.path()[0].as_str(), "Specs");
        assert_eq!(uri.path()[1].as_str(), "API_v1");
        assert_eq!(uri.view(), Some(ProgressiveView::Overview));
        assert!(uri.is_pinned());
        assert_eq!(uri.revision().unwrap().as_bytes(), &[0; 32]);
    }

    #[test]
    fn accepts_each_canonical_query_shape() {
        let base = "ruv://a/t/user/u/skills";
        for suffix in [
            "",
            "?view=abstract",
            "?view=overview",
            "?view=content",
            &format!("?rev={ZERO_REVISION}"),
            &format!("?rev={ZERO_REVISION}&view=content"),
        ] {
            let text = format!("{base}{suffix}");
            assert_eq!(RuvUri::parse(&text).unwrap().to_string(), text);
        }
    }

    #[test]
    fn all_registered_enums_are_exact_and_lowercase() {
        for (text, kind) in [
            ("agent", SubjectKind::Agent),
            ("user", SubjectKind::User),
            ("service", SubjectKind::Service),
            ("team", SubjectKind::Team),
        ] {
            assert_eq!(text.parse::<SubjectKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), text);
        }
        for (text, collection) in [
            ("memory", Collection::Memory),
            ("resources", Collection::Resources),
            ("skills", Collection::Skills),
        ] {
            assert_eq!(text.parse::<Collection>().unwrap(), collection);
            assert_eq!(collection.to_string(), text);
        }
        assert_eq!(
            "Agent".parse::<SubjectKind>(),
            Err(UriError::InvalidSubjectKind)
        );
        assert_eq!(
            "Memory".parse::<Collection>(),
            Err(UriError::InvalidCollection)
        );
        assert_eq!(
            "Overview".parse::<ProgressiveView>(),
            Err(UriError::InvalidView)
        );
    }

    #[test]
    fn authority_enforces_dns_limits_and_canonical_form() {
        assert!(Authority::new("a").is_ok());
        assert!(Authority::new(&"a".repeat(63)).is_ok());
        assert_eq!(
            Authority::new(&"a".repeat(64)),
            Err(UriError::InvalidAuthority)
        );
        assert_eq!(
            Authority::new("-a.example"),
            Err(UriError::InvalidAuthority)
        );
        assert_eq!(
            Authority::new("a-.example"),
            Err(UriError::InvalidAuthority)
        );
        assert_eq!(
            Authority::new("a..example"),
            Err(UriError::InvalidAuthority)
        );
        assert_eq!(Authority::new("A.example"), Err(UriError::InvalidAuthority));
        assert_eq!(
            Authority::new("a.example."),
            Err(UriError::InvalidAuthority)
        );

        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest.len(), 253);
        assert!(Authority::new(&longest).is_ok());
        let too_long = format!("{longest}.e");
        assert_eq!(Authority::new(&too_long), Err(UriError::InvalidAuthority));
    }

    #[test]
    fn identifiers_are_bounded_lowercase_slugs() {
        for valid in ["a", "0", "agent-42", &"z".repeat(63)] {
            assert!(TenantId::new(valid).is_ok());
            assert!(SubjectId::new(valid).is_ok());
        }
        for invalid in [
            "",
            "Agent",
            "-agent",
            "agent-",
            "agent_name",
            &"a".repeat(64),
        ] {
            assert!(TenantId::new(invalid).is_err());
            assert!(SubjectId::new(invalid).is_err());
        }
    }

    #[test]
    fn path_segments_are_ascii_unreserved_and_case_sensitive() {
        for valid in ["A", "readme.md", "API_v1", "x~y", &"z".repeat(128)] {
            assert_eq!(PathSegment::new(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", ".", "..", "a b", "a+b", "a:b", "a?b", &"z".repeat(129)] {
            assert!(PathSegment::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn rejects_non_ascii_percent_fragments_credentials_and_ports() {
        let cases = [
            (
                "ruv://context.example/acmé/agent/a/memory",
                UriError::NonAscii,
            ),
            (
                "ruv://context.example/acme/agent/a/memory/%2e%2e",
                UriError::PercentEncodingNotAllowed,
            ),
            (
                "ruv://context.example/acme/agent/a/memory#fragment",
                UriError::FragmentNotAllowed,
            ),
            (
                "ruv://user@context.example/acme/agent/a/memory",
                UriError::CredentialsNotAllowed,
            ),
            (
                "ruv://context.example:443/acme/agent/a/memory",
                UriError::PortNotAllowed,
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(RuvUri::parse(text), Err(expected), "case {text}");
        }
    }

    #[test]
    fn rejects_missing_empty_trailing_and_dot_paths() {
        assert_eq!(
            RuvUri::parse("ruv://a/t/agent/id"),
            Err(UriError::MissingComponent)
        );
        assert_eq!(
            RuvUri::parse("ruv://a/t/agent/id/memory/"),
            Err(UriError::TrailingSlash)
        );
        assert_eq!(
            RuvUri::parse("ruv://a/t/agent/id/memory//x"),
            Err(UriError::EmptyPathSegment)
        );
        assert_eq!(
            RuvUri::parse("ruv://a/t/agent/id/memory/.."),
            Err(UriError::DotSegment)
        );
    }

    #[test]
    fn rejects_noncanonical_scheme_and_structural_case() {
        for text in [
            "RUV://a/t/agent/id/memory",
            "ruv:/a/t/agent/id/memory",
            "ruv://A/t/agent/id/memory",
            "ruv://a/T/agent/id/memory",
            "ruv://a/t/Agent/id/memory",
            "ruv://a/t/agent/ID/memory",
            "ruv://a/t/agent/id/Memory",
        ] {
            assert!(RuvUri::parse(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn rejects_unknown_duplicate_reordered_or_malformed_query() {
        let base = "ruv://a/t/agent/id/memory";
        for suffix in [
            "?",
            "?rev",
            "?rev=",
            "?view=",
            "?other=x",
            "?view=abstract&view=content",
            &format!("?rev={ZERO_REVISION}&rev={ZERO_REVISION}"),
            &format!("?view=overview&rev={ZERO_REVISION}"),
            &format!("?rev={ZERO_REVISION}&"),
            &format!("?rev={ZERO_REVISION}&view=overview&other=x"),
        ] {
            assert!(
                RuvUri::parse(&format!("{base}{suffix}")).is_err(),
                "accepted {suffix}"
            );
        }
    }

    #[test]
    fn revision_requires_exact_lowercase_sha256_encoding() {
        assert!(ZERO_REVISION.parse::<Revision>().is_ok());
        for invalid in [
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
            "sha256:0000",
            "sha256:000000000000000000000000000000000000000000000000000000000000000G",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha512:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(invalid.parse::<Revision>(), Err(UriError::InvalidRevision));
        }
        let digest = Revision::from_bytes([0xab; 32]);
        assert_eq!(
            digest.to_string(),
            "sha256:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn builder_and_pinned_wrapper_preserve_invariants() {
        let uri = RuvUriBuilder::new(
            Authority::new("context.example").unwrap(),
            TenantId::new("acme").unwrap(),
            Subject::new(SubjectKind::Service, SubjectId::new("indexer").unwrap()),
            Collection::Resources,
        )
        .path_segment(PathSegment::new("Docs").unwrap())
        .revision(Revision::from_bytes([7; 32]))
        .view(ProgressiveView::Content)
        .build_pinned()
        .unwrap();
        assert_eq!(uri.revision(), Revision::from_bytes([7; 32]));
        assert_eq!(uri.as_uri().path()[0].as_str(), "Docs");

        let unpinned = RuvUri::parse("ruv://a/t/team/core/skills").unwrap();
        assert_eq!(
            PinnedRuvUri::try_from(unpinned),
            Err(UriError::RevisionRequired)
        );
    }

    #[test]
    fn aggregate_path_limits_are_enforced() {
        let base = "ruv://a/t/agent/id/memory";
        let too_many = format!("{base}/{}", vec!["x"; 33].join("/"));
        assert_eq!(RuvUri::parse(&too_many), Err(UriError::TooManyPathSegments));

        let long_segments = vec!["x".repeat(128); 9];
        let too_long = format!("{base}/{}", long_segments.join("/"));
        assert_eq!(RuvUri::parse(&too_long), Err(UriError::PathTooLong));

        let exactly = vec!["x".repeat(127); 8].join("/");
        assert_eq!(exactly.len(), 1_023);
        assert!(RuvUri::parse(&format!("{base}/{exactly}")).is_ok());
    }

    #[test]
    fn complete_uri_limit_is_checked_before_other_parsing() {
        let oversized = format!("ruv://{}", "a".repeat(MAX_URI_BYTES));
        assert_eq!(RuvUri::parse(&oversized), Err(UriError::UriTooLong));
    }

    proptest! {
        #[test]
        fn canonical_generated_uris_round_trip(
            tenant in "[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?",
            subject_id in "[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?",
            path in prop::collection::vec("[A-Za-z0-9_~-]{1,16}", 0..8),
            digest in any::<[u8; 32]>(),
            pinned in any::<bool>(),
            view_index in 0_u8..4,
        ) {
            let mut builder = RuvUriBuilder::new(
                Authority::new("context.example").unwrap(),
                TenantId::new(&tenant).unwrap(),
                Subject::new(SubjectKind::Agent, SubjectId::new(&subject_id).unwrap()),
                Collection::Memory,
            );
            for segment in path {
                builder = builder.path_segment(PathSegment::new(&segment).unwrap());
            }
            if pinned {
                builder = builder.revision(Revision::from_bytes(digest));
            }
            if let Some(view) = match view_index {
                0 => None,
                1 => Some(ProgressiveView::Abstract),
                2 => Some(ProgressiveView::Overview),
                _ => Some(ProgressiveView::Content),
            } {
                builder = builder.view(view);
            }
            let uri = builder.build().unwrap();
            let text = uri.to_string();
            prop_assert_eq!(RuvUri::parse(&text), Ok(uri));
        }

        #[test]
        fn percent_is_rejected_at_every_path_position(
            prefix in "[A-Za-z0-9_~-]{0,16}",
            suffix in "[A-Za-z0-9_~-]{0,16}",
        ) {
            let text = format!("ruv://a/t/agent/id/memory/{prefix}%2f{suffix}");
            prop_assert_eq!(RuvUri::parse(&text), Err(UriError::PercentEncodingNotAllowed));
        }
    }
}
