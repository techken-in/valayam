//! Enterprise web crawler — async crawling with SPA/JS route extraction.
//!
//! Crawls websites to discover endpoints, forms, links, and JS routes.
//! Supports rate limiting, domain scope control, and auth header injection.
//! Includes JS/SPA route extraction, WASM decompilation, and OpenAPI parsing.

pub mod parsers;
pub mod spider;
pub mod wordlists;

pub use spider::Crawler;
