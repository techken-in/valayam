//! DSL helper functions for template expressions.
//!
//! Provides reusable helper functions used within scan templates for
//! Base64, Hex, URL encoding, MD5/SHA hashing, and data transformation.
//! Evaluated dynamically after variable substitution.

/// Summary of available helper functions — forward-compatible.
#[non_exhaustive]
pub struct HelpersSummary {
    pub encoding_helpers: usize,
    pub hashing_helpers: usize,
    pub transformation_helpers: usize,
}
