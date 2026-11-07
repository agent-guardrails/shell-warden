//! No-op proc-macro that registers the `serde` helper attribute.
//!
//! The config-v2 grammar declarations in `src/checker/grammar.rs` must keep
//! their documented `#[serde(...)]` attributes verbatim (the
//! `agent-guardrails/docs` grammar-drift guard snapshots the marked region
//! token-for-token), while `RemainderPolicy` and `TokenSelector` carry
//! hand-written canonical deserialization/serialization instead of derives.
//! Serde's helper attributes only resolve when a serde derive sits on the
//! item, so this crate exists purely to register the attribute — it emits
//! no code and changes no semantics.

use proc_macro::TokenStream;

/// Registers `serde` helper attributes on the attributed item; emits nothing.
#[proc_macro_derive(GrammarDocAttrs, attributes(serde))]
pub fn grammar_doc_attrs(_: TokenStream) -> TokenStream {
    TokenStream::new()
}
