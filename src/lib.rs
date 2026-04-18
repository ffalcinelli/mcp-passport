//! # mcp-passport: Secure Layer 7 Proxy for MCP
//!
//! `mcp-passport` is a high-performance, secure proxy designed to protect
//! Model Context Protocol (MCP) servers using industry-standard OIDC and FAPI 2.0 security.
//!
//! ## Core Components
//! - [`proxy`]: The Layer 7 bridge that multiplexes JSON-RPC over stdio ↔ HTTP/SSE.
//! - [`auth`]: OIDC/OAuth2 flow implementation, including PAR and DPoP support.
//! - [`crypto`]: Cryptographic primitives for DPoP (P-256 JWT signing).
//! - [`vault`]: Secure OS-native storage for tokens and ephemeral keys.
//! - [`config`]: Configuration management for the proxy.

pub mod auth;
pub mod config;
pub mod crypto;
pub mod proxy;
pub mod vault;

/// Shared result type for the crate.
pub type Result<T> = anyhow::Result<T>;
