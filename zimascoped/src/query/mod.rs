//! Selector IR and resolution seam (ADR-0005).
//!
//! Every control-plane feature that locates resources and acts on them shares
//! [`Selector`] as its query language and [`EvidenceResolver`] as the seam
//! that turns selectors into bounded kernel-matchable targets. Feature code
//! never queries storage directly.

mod lower;
mod resolver;
mod selector;

pub use lower::UnsupportedQuery;
pub(crate) use resolver::{ApplicationComms, SystemEvidenceResolver};
pub use resolver::{
    Coverage, EvidenceResolver, MatchTarget, Resolution, ResolveContext, ResolveError,
};
pub use selector::{KernelPlan, Refresh, Selector};
