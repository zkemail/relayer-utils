//! Runtime regex extraction utilities for email parsing
//!
//! This module provides runtime regex extraction functionality using
//! DecomposedRegexConfig from zk-regex-compiler. It is separate from
//! circuit generation and focuses on runtime text extraction.
//!
//! # Design: Hybrid Extraction Approach
//!
//! This module implements a hybrid approach for capture group handling:
//!
//! - **With NFAGraph**: Uses compiler's capture groups for alignment with circuits
//! - **Without NFAGraph**: Creates own capture groups based on PublicPattern parts
//!
//! This ensures consistency when used in circuit contexts while maintaining
//! standalone functionality.

pub mod extract;
pub mod padding;
pub mod patterns;
pub mod types;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Re-export main types and functions
pub use extract::*;
pub use padding::*;
pub use patterns::*;
pub use types::*;

// Re-export NFAGraph from compiler for convenience
pub use zk_regex_compiler::NFAGraph;
