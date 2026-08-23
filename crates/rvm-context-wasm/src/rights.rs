//! Capability rights, named the way the `ruv://` operations name them.

use crate::error::argument_error;
use rvm_context::capability::ContextOperation;
use rvm_types::CapRights;
use wasm_bindgen::prelude::*;

/// Parses the registered lowercase spelling of a governed operation.
pub(crate) fn parse_operation(name: &str) -> Result<ContextOperation, JsValue> {
    Ok(match name {
        "resolve" => ContextOperation::Resolve,
        "list" => ContextOperation::List,
        "tree" => ContextOperation::Tree,
        "read" => ContextOperation::Read,
        "search" => ContextOperation::Search,
        "history" => ContextOperation::History,
        "verify" => ContextOperation::Verify,
        "put" => ContextOperation::Put,
        "compareAndSwapAlias" => ContextOperation::CompareAndSwapAlias,
        "forget" => ContextOperation::Forget,
        "execute" => ContextOperation::Execute,
        "grant" => ContextOperation::Grant,
        "revoke" => ContextOperation::Revoke,
        "sealReceipt" => ContextOperation::SealReceipt,
        other => return Err(argument_error("UnknownOperation", &alloc_format(other))),
    })
}

fn alloc_format(name: &str) -> String {
    format!("unknown context operation: {name}")
}

const RIGHT_NAMES: [(&str, CapRights); 7] = [
    ("read", CapRights::READ),
    ("write", CapRights::WRITE),
    ("grant", CapRights::GRANT),
    ("revoke", CapRights::REVOKE),
    ("execute", CapRights::EXECUTE),
    ("prove", CapRights::PROVE),
    ("grantOnce", CapRights::GRANT_ONCE),
];

/// A set of capability rights.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Rights {
    inner: CapRights,
}

impl Rights {
    pub(crate) fn inner(self) -> CapRights {
        self.inner
    }
}

#[wasm_bindgen]
impl Rights {
    /// The empty rights set.
    #[must_use]
    pub fn none() -> Rights {
        Self {
            inner: CapRights::empty(),
        }
    }

    /// Builds a rights set from names.
    ///
    /// Valid names are `read`, `write`, `grant`, `revoke`, `execute`, `prove`,
    /// and `grantOnce`.
    ///
    /// # Errors
    ///
    /// Throws `ContextArgumentError` with code `UnknownRight` for any
    /// unrecognized name.
    #[wasm_bindgen(js_name = fromNames)]
    pub fn from_names(names: Vec<String>) -> Result<Rights, JsValue> {
        let mut inner = CapRights::empty();
        for name in names {
            let found = RIGHT_NAMES
                .iter()
                .find(|(candidate, _)| *candidate == name.as_str())
                .ok_or_else(|| {
                    argument_error("UnknownRight", &format!("unknown capability right: {name}"))
                })?;
            inner = inner.union(found.1);
        }
        Ok(Self { inner })
    }

    /// The exact rights a governed operation requires.
    ///
    /// This is the authoritative mapping from the core crate, so a caller
    /// never has to guess which rights an operation needs.
    ///
    /// # Errors
    ///
    /// Throws `ContextArgumentError` with code `UnknownOperation` when
    /// `operation` is not a registered operation name.
    #[wasm_bindgen(js_name = forOperation)]
    pub fn for_operation(operation: &str) -> Result<Rights, JsValue> {
        Ok(Self {
            inner: parse_operation(operation)?.required_rights(),
        })
    }

    /// The union of the rights every named operation requires.
    ///
    /// # Errors
    ///
    /// Throws `ContextArgumentError` when any name is not a registered
    /// operation.
    #[wasm_bindgen(js_name = forOperations)]
    pub fn for_operations(operations: Vec<String>) -> Result<Rights, JsValue> {
        let mut inner = CapRights::empty();
        for operation in operations {
            inner = inner.union(parse_operation(&operation)?.required_rights());
        }
        Ok(Self { inner })
    }

    /// The stable bit representation.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bits(&self) -> u8 {
        self.inner.bits()
    }

    /// The names of the rights in this set.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        RIGHT_NAMES
            .iter()
            .filter(|(_, right)| self.inner.contains(*right))
            .map(|(name, _)| (*name).into())
            .collect()
    }

    /// Combines two rights sets.
    #[must_use]
    pub fn union(&self, other: &Rights) -> Rights {
        Self {
            inner: self.inner.union(other.inner),
        }
    }

    /// Whether `other` is equal to or narrower than this set.
    #[must_use]
    pub fn contains(&self, other: &Rights) -> bool {
        self.inner.contains(other.inner)
    }
}

/// The registered governed operation names.
#[wasm_bindgen(js_name = operationNames)]
#[must_use]
pub fn operation_names() -> Vec<String> {
    [
        "resolve",
        "list",
        "tree",
        "read",
        "search",
        "history",
        "verify",
        "put",
        "compareAndSwapAlias",
        "forget",
        "execute",
        "grant",
        "revoke",
        "sealReceipt",
    ]
    .iter()
    .map(|name| (*name).into())
    .collect()
}
