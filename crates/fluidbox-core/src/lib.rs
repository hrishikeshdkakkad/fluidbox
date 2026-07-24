//! fluidbox-core — pure domain logic for the fluidbox control plane.
//!
//! No I/O lives here: the state machine, the canonical event schema, the
//! policy engine (including autonomy resolution), redaction, usage/cost
//! types, and the execution-provider extension trait (`ExecutionProvider`).
//! There is deliberately no `Harness` trait — a harness is a runner image
//! implementing the HTTP runner contract (see `fluidbox-server::harness`).

pub mod capability;
pub mod event;
pub mod netpolicy;
pub mod policy;
pub mod schedule;
pub mod schema_guard;
pub mod spec;
pub mod state;
pub mod tools;
pub mod traits;
pub mod usage;

pub use event::{EventBody, EventEnvelope, Redacted, Redactor};
pub use policy::{EvaluationOutcome, Policy, ToolCallRequest, Verdict};
pub use spec::{
    Autonomy, Budgets, InvocationContext, InvocationKind, ResultDestination, RunSpec, TrustTier,
};
pub use state::SessionStatus;
