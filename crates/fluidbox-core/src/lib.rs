//! fluidbox-core — pure domain logic for the fluidbox control plane.
//!
//! No I/O lives here: the state machine, the canonical event schema, the
//! policy engine (including autonomy resolution), redaction, usage/cost
//! types, and the extension traits (`ExecutionProvider`, `Harness`).

pub mod event;
pub mod policy;
pub mod schedule;
pub mod spec;
pub mod state;
pub mod traits;
pub mod usage;

pub use event::{EventBody, EventEnvelope, Redacted, Redactor};
pub use policy::{EvaluationOutcome, Policy, ToolCallRequest, Verdict};
pub use spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, RunSpec, TrustTier,
};
pub use state::SessionStatus;
