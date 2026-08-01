//! Recipes: versioned templates that stamp ordinary fluidbox objects
//! (policies, agents, trigger subscriptions, schedules, runs) from a small set
//! of validated parameters (design docs/plans/2026-07-31-enterprise-recipes-design.md).
//!
//! This module is the pure domain half: definition shape + validation, the
//! parameter contract (a JSON-Schema document with `x-fluidbox` widget
//! annotations), and deterministic rendering of a definition against concrete
//! parameter values. Everything here is I/O-free and unit-tested; the server's
//! deploy engine layers reference resolution (connections, models, cron) and
//! the atomic stamp on top.
//!
//! Two rendering mechanisms, one pass (design §5):
//! - a string that is EXACTLY `"$param:name"` (optionally `"$param:name.field"`)
//!   is replaced by the TYPED parameter value — arrays, booleans, numbers,
//!   objects — or dropped (key/element removed) when an optional parameter is
//!   absent;
//! - any other string gets `{{recipe.<param>}}` / `{{instance.name}}`
//!   interpolation (string-coercible params only). Runtime placeholders
//!   (`{{pr_number}}`, `{{fire_time}}`, …) are LEFT UNTOUCHED for the existing
//!   event/schedule renderer — recipe-time and run-time templating never
//!   collide because they use disjoint namespaces.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The one definition schema version this build understands. A definition
/// naming a NEWER version is refused loudly (an older server must never
/// half-understand a newer recipe), mirroring the RunSpec back-compat posture.
pub const DEFINITION_SCHEMA_VERSION: u64 = 1;

/// Bounds on the definition itself — it is operator/tenant-authored (custom
/// recipes), i.e. untrusted input to the deploy engine.
pub const MAX_AGENTS: usize = 8;
pub const MAX_SUBSCRIPTIONS: usize = 8;
pub const MAX_SUCCESS_CRITERIA: usize = 16;

/// Bounds on the user-supplied params blob (untrusted).
pub const MAX_PARAMS_BYTES: usize = 64 * 1024;
pub const MAX_PARAMS_DEPTH: usize = 16;

// ─── Definition shape ─────────────────────────────────────────────────────

/// A recipe version's `definition` column, strictly parsed
/// (`deny_unknown_fields`): the stamp plan. Leaves that admit parameter
/// injection are `Value`s here; [`RenderedRecipe`] is the post-render, strictly
/// typed shape the deploy engine consumes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeDefinition {
    /// Must equal [`DEFINITION_SCHEMA_VERSION`].
    pub schema: u64,
    /// Detail-page body (markdown). Display-only.
    #[serde(default)]
    pub summary_md: Option<String>,
    /// What "working" means for this recipe — surfaced on the detail page and
    /// the instance page. Display-only, but first-class: every studied
    /// enterprise platform is converging on success criteria as the eval hook.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// Optional dedicated policy stamped per instance (named
    /// `<instance>-policy`). Omitted ⇒ stamped agents use the org `default`
    /// policy. The content must parse as a canonical [`crate::policy::Policy`].
    #[serde(default)]
    pub policy: Option<RecipePolicy>,
    /// 1..=MAX_AGENTS agents. Multi-agent recipes (fan-out panels) list one
    /// entry per role.
    pub agents: Vec<RecipeAgent>,
    /// 0..=MAX_SUBSCRIPTIONS trigger subscriptions wiring agents to
    /// api/schedule/event triggers.
    #[serde(default)]
    pub subscriptions: Vec<RecipeSubscription>,
    /// Optional instant run fired right after a successful deploy (through
    /// `run_service::create_run`, after the stamp transaction commits).
    #[serde(default)]
    pub first_run: Option<RecipeFirstRun>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipePolicy {
    /// Canonical Policy document (0026 shape). Validated at definition
    /// validation time — a recipe carrying an unparsable policy is refused
    /// before it can ever be deployed.
    pub content: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeAgent {
    /// Stable role id within the recipe (`[a-z0-9-]{1,64}`), unique across
    /// the recipe's agents. Instance objects record it as their `slot`.
    pub slot: String,
    /// Templated display name (string after render).
    pub name: Value,
    pub harness: String,
    #[serde(default)]
    pub model: Option<Value>,
    #[serde(default)]
    pub system_prompt: Option<Value>,
    /// Budgets object (spec::Budgets shape) — tighten-only downstream.
    #[serde(default)]
    pub budgets: Option<Value>,
    /// Sandbox capability bundle names (pin-at-attach preserved downstream).
    #[serde(default)]
    pub capability_bundles: Option<Value>,
    /// Brokered connection requirements; validated post-render via
    /// `capability::validate_requirements`.
    #[serde(default)]
    pub connection_requirements: Option<Value>,
    /// Default workspace (WorkspaceInput shape) — validated server-side
    /// post-render exactly like `POST /v1/agents`' `default_workspace`.
    #[serde(default)]
    pub workspace: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSubscription {
    /// Stable id within the recipe (`[a-z0-9-]{1,64}`), unique across the
    /// recipe's subscriptions.
    pub slot: String,
    /// Which recipe agent this subscription borrows — must name an
    /// `agents[].slot`.
    pub agent_slot: String,
    /// `api` | `schedule` | `event` — fixed per recipe version (trigger kind
    /// is immutable on the stamped object too).
    pub kind: String,
    /// Templated display name.
    pub name: Value,
    #[serde(default)]
    pub task_template: Option<Value>,
    #[serde(default)]
    pub autonomous: Option<Value>,
    #[serde(default)]
    pub concurrency_policy: Option<Value>,
    /// Event kind: the connection the events arrive on (a connection
    /// reference param).
    #[serde(default)]
    pub connection: Option<Value>,
    #[serde(default)]
    pub repositories: Option<Value>,
    #[serde(default)]
    pub events: Option<Value>,
    #[serde(default)]
    pub publish: Option<Value>,
    /// Schedule kind: the clock.
    #[serde(default)]
    pub schedule: Option<RecipeSchedule>,
    #[serde(default)]
    pub allow_task_override: Option<Value>,
    #[serde(default)]
    pub allow_workspace_override: Option<Value>,
    /// Optional signed-webhook destination URL.
    #[serde(default)]
    pub callback_url: Option<Value>,
    #[serde(default)]
    pub budgets: Option<Value>,
    /// Capability keep-list (remove-only downstream).
    #[serde(default)]
    pub capabilities: Option<Value>,
    /// Subscription workspace override (WorkspaceInput shape).
    #[serde(default)]
    pub workspace: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSchedule {
    pub cron: Value,
    #[serde(default)]
    pub timezone: Option<Value>,
    #[serde(default)]
    pub missed_run_policy: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeFirstRun {
    pub agent_slot: String,
    pub task: Value,
    #[serde(default)]
    pub autonomous: Option<Value>,
}

pub const SUBSCRIPTION_KINDS: &[&str] = &["api", "schedule", "event"];

fn valid_slot(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl RecipeDefinition {
    /// Parse + structurally validate a stored/incoming definition. Everything
    /// checkable BEFORE parameters exist is checked here; post-render checks
    /// (workspace shapes, connection requirements, cron, model) live with the
    /// deploy engine where their context lives.
    pub fn parse(value: &Value) -> Result<RecipeDefinition, String> {
        let def: RecipeDefinition = serde_json::from_value(value.clone())
            .map_err(|e| format!("definition does not parse: {e}"))?;
        def.validate()?;
        Ok(def)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DEFINITION_SCHEMA_VERSION {
            return Err(format!(
                "definition schema {} is not supported (this build understands {})",
                self.schema, DEFINITION_SCHEMA_VERSION
            ));
        }
        if self.agents.is_empty() {
            return Err("definition declares no agents".into());
        }
        if self.agents.len() > MAX_AGENTS {
            return Err(format!("definition declares more than {MAX_AGENTS} agents"));
        }
        if self.subscriptions.len() > MAX_SUBSCRIPTIONS {
            return Err(format!(
                "definition declares more than {MAX_SUBSCRIPTIONS} subscriptions"
            ));
        }
        if self.success_criteria.len() > MAX_SUCCESS_CRITERIA {
            return Err(format!(
                "definition declares more than {MAX_SUCCESS_CRITERIA} success criteria"
            ));
        }
        let mut agent_slots = BTreeSet::new();
        for a in &self.agents {
            if !valid_slot(&a.slot) {
                return Err(format!(
                    "agent slot '{}' must be 1-64 chars of [a-z0-9-]",
                    a.slot
                ));
            }
            if !agent_slots.insert(a.slot.as_str()) {
                return Err(format!("duplicate agent slot '{}'", a.slot));
            }
        }
        let mut sub_slots = BTreeSet::new();
        for s in &self.subscriptions {
            if !valid_slot(&s.slot) {
                return Err(format!(
                    "subscription slot '{}' must be 1-64 chars of [a-z0-9-]",
                    s.slot
                ));
            }
            if !sub_slots.insert(s.slot.as_str()) {
                return Err(format!("duplicate subscription slot '{}'", s.slot));
            }
            if !agent_slots.contains(s.agent_slot.as_str()) {
                return Err(format!(
                    "subscription '{}' names unknown agent slot '{}'",
                    s.slot, s.agent_slot
                ));
            }
            if !SUBSCRIPTION_KINDS.contains(&s.kind.as_str()) {
                return Err(format!(
                    "subscription '{}' kind must be one of {}",
                    s.slot,
                    SUBSCRIPTION_KINDS.join(" | ")
                ));
            }
            match s.kind.as_str() {
                "schedule" if s.schedule.is_none() => {
                    return Err(format!(
                        "subscription '{}' is schedule-kind but has no schedule",
                        s.slot
                    ));
                }
                "event" if s.connection.is_none() => {
                    return Err(format!(
                        "subscription '{}' is event-kind but has no connection",
                        s.slot
                    ));
                }
                "api" | "schedule" if s.connection.is_some() => {
                    return Err(format!(
                        "subscription '{}' is {}-kind but names a connection",
                        s.slot, s.kind
                    ));
                }
                "api" | "event" if s.schedule.is_some() => {
                    return Err(format!(
                        "subscription '{}' is {}-kind but carries a schedule",
                        s.slot, s.kind
                    ));
                }
                _ => {}
            }
        }
        if let Some(fr) = &self.first_run {
            if !agent_slots.contains(fr.agent_slot.as_str()) {
                return Err(format!(
                    "first_run names unknown agent slot '{}'",
                    fr.agent_slot
                ));
            }
        }
        if let Some(p) = &self.policy {
            crate::policy::Policy::parse_strict(p.content.clone())
                .map_err(|e| format!("recipe policy content does not parse: {e}"))?;
        }
        Ok(())
    }
}

// ─── Parameter contract ───────────────────────────────────────────────────

/// One renderable parameter derived from a `params_schema` property + its
/// `x-fluidbox` annotation. The server uses the widget for SEMANTIC validation
/// (connection exists, cron parses, model belongs to harness); the dashboard
/// renders the matching input. Every catalog recipe's schema must yield a full
/// spec list — a property no widget can render is refused at recipe
/// create/validate time, so the catalog is always renderable.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ParamSpec {
    pub name: String,
    pub title: String,
    pub description: Option<String>,
    pub required: bool,
    pub default: Option<Value>,
    pub widget: ParamWidget,
    /// `enum` values for Select widgets (also honored on StringList items).
    pub choices: Option<Vec<Value>>,
    /// Display grouping/help extras passed through verbatim (`x-fluidbox`
    /// minus the keys the widget consumed). Presentation-only.
    pub ui: Option<Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParamWidget {
    Text,
    Textarea,
    Url,
    Number,
    Boolean,
    Select,
    StringList,
    Repositories,
    Cron,
    Timezone,
    Model {
        harness: String,
    },
    /// Pick an existing tenant-visible connection. `provider` filters (e.g.
    /// "github"); `mcp` restricts to MCP-capable (brokered) connections.
    Connection {
        provider: Option<String>,
        mcp: bool,
    },
    /// Pick tool names from another connection param's live snapshot.
    ConnectionTools {
        connection_param: String,
    },
    Events,
}

/// There is deliberately NO secret widget: secrets are never recipe
/// parameters. A schema asking for one is refused by name so the error
/// teaches the model ("reference a connection instead").
const FORBIDDEN_WIDGETS: &[&str] = &["secret", "password", "token", "api_key"];

/// Walk a params_schema into renderable [`ParamSpec`]s. Errors name the
/// property and the reason. The schema must already have passed
/// [`crate::schema_guard::guard_schema`] (the caller's job — the guard is
/// shared with frozen tool schemas).
pub fn param_specs(schema: &Value) -> Result<Vec<ParamSpec>, String> {
    let obj = schema
        .as_object()
        .ok_or("params_schema must be a JSON object")?;
    if obj.get("type").and_then(Value::as_str) != Some("object") {
        return Err("params_schema must declare \"type\": \"object\"".into());
    }
    // additionalProperties:false is required so unknown params are rejected by
    // the same validator that checks known ones — one enforcement point.
    if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Err("params_schema must set \"additionalProperties\": false".into());
    }
    let required: BTreeSet<&str> = obj
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let props = obj
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("params_schema must declare \"properties\"")?;
    // Deterministic order: x-fluidbox-ui.order first, then remaining
    // properties in schema (insertion) order.
    let order: Vec<String> = {
        let explicit: Vec<String> = obj
            .get("x-fluidbox-ui")
            .and_then(|u| u.get("order"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let mut out = explicit.clone();
        for k in props.keys() {
            if !explicit.contains(k) {
                out.push(k.clone());
            }
        }
        out.retain(|k| props.contains_key(k));
        out
    };
    let mut specs = Vec::with_capacity(props.len());
    for name in order {
        let p = &props[&name];
        let po = p
            .as_object()
            .ok_or_else(|| format!("param '{name}' must be a schema object"))?;
        let xf = po.get("x-fluidbox").and_then(Value::as_object);
        let widget_name = xf
            .and_then(|x| x.get("widget"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(w) = widget_name.as_deref() {
            if FORBIDDEN_WIDGETS.contains(&w) {
                return Err(format!(
                    "param '{name}': secrets are never recipe parameters — reference a connection instead"
                ));
            }
        }
        let ptype = po.get("type").and_then(Value::as_str);
        let has_enum = po.get("enum").and_then(Value::as_array).is_some();
        let widget = match widget_name.as_deref() {
            Some("text") => ParamWidget::Text,
            Some("textarea") => ParamWidget::Textarea,
            Some("url") => ParamWidget::Url,
            Some("cron") => ParamWidget::Cron,
            Some("timezone") => ParamWidget::Timezone,
            Some("repositories") => ParamWidget::Repositories,
            Some("events") => ParamWidget::Events,
            Some("model") => {
                let harness = xf
                    .and_then(|x| x.get("harness"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("param '{name}': model widget needs \"harness\""))?;
                ParamWidget::Model {
                    harness: harness.to_string(),
                }
            }
            Some("connection") => ParamWidget::Connection {
                provider: xf
                    .and_then(|x| x.get("provider"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                mcp: xf
                    .and_then(|x| x.get("mcp"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            Some("connection_tools") => {
                let cp = xf
                    .and_then(|x| x.get("connection_param"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        format!(
                            "param '{name}': connection_tools widget needs \"connection_param\""
                        )
                    })?;
                if !props.contains_key(cp) {
                    return Err(format!(
                        "param '{name}': connection_param '{cp}' is not a declared param"
                    ));
                }
                ParamWidget::ConnectionTools {
                    connection_param: cp.to_string(),
                }
            }
            Some(other) => return Err(format!("param '{name}': unknown widget '{other}'")),
            // No explicit widget: infer from the schema type.
            None => match (ptype, has_enum) {
                (_, true) => ParamWidget::Select,
                (Some("string"), _) => ParamWidget::Text,
                (Some("boolean"), _) => ParamWidget::Boolean,
                (Some("integer") | Some("number"), _) => ParamWidget::Number,
                (Some("array"), _) => {
                    let items_str = po
                        .get("items")
                        .and_then(|i| i.get("type"))
                        .and_then(Value::as_str)
                        == Some("string")
                        || po.get("items").and_then(|i| i.get("enum")).is_some();
                    if items_str {
                        ParamWidget::StringList
                    } else {
                        return Err(format!(
                            "param '{name}': array params must have string items"
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "param '{name}': no renderable widget for this schema shape"
                    ))
                }
            },
        };
        // Widget/type coherence for the reference widgets (they carry ids —
        // must be strings / string arrays).
        match &widget {
            ParamWidget::Connection { .. }
            | ParamWidget::Cron
            | ParamWidget::Timezone
            | ParamWidget::Url
            | ParamWidget::Text
            | ParamWidget::Textarea
            | ParamWidget::Model { .. }
                if ptype != Some("string") =>
            {
                return Err(format!(
                    "param '{name}': this widget requires \"type\": \"string\""
                ));
            }
            ParamWidget::Repositories
            | ParamWidget::ConnectionTools { .. }
            | ParamWidget::Events
                if ptype != Some("array") =>
            {
                return Err(format!(
                    "param '{name}': this widget requires \"type\": \"array\""
                ));
            }
            _ => {}
        }
        let choices = po
            .get("enum")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| {
                po.get("items")
                    .and_then(|i| i.get("enum"))
                    .and_then(Value::as_array)
                    .cloned()
            });
        specs.push(ParamSpec {
            name: name.clone(),
            title: po
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(&name)
                .to_string(),
            description: po
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string),
            required: required.contains(name.as_str()),
            default: po.get("default").cloned(),
            widget,
            choices,
            ui: xf.map(|x| Value::Object(x.clone())),
        });
    }
    Ok(specs)
}

/// Fill absent optional params with their schema defaults. Returns the
/// effective params object (provided values win; defaults fill holes; nothing
/// else is added). The caller validates the RESULT against the schema, so a
/// bad default cannot sneak past validation.
pub fn apply_defaults(schema: &Value, params: &Map<String, Value>) -> Map<String, Value> {
    let mut out = params.clone();
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (name, p) in props {
            if !out.contains_key(name) {
                if let Some(d) = p.get("default") {
                    out.insert(name.clone(), d.clone());
                }
            }
        }
    }
    out
}

/// Bound + structurally validate a caller-supplied params object against the
/// recipe's frozen schema. Errors are JSON-pointer paths (never values — the
/// blob is caller data but the error strings travel into responses and logs).
pub fn validate_params(schema: &Value, params: &Map<String, Value>) -> Result<(), Vec<String>> {
    let blob = Value::Object(params.clone());
    let size = serde_json::to_vec(&blob)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if size > MAX_PARAMS_BYTES {
        return Err(vec![format!("params exceed {MAX_PARAMS_BYTES} bytes")]);
    }
    if !bounded_depth(&blob, MAX_PARAMS_DEPTH) {
        return Err(vec![format!(
            "params nest deeper than {MAX_PARAMS_DEPTH} levels"
        )]);
    }
    match crate::schema_guard::validate_args(
        schema,
        &blob,
        crate::schema_guard::SchemaDialect::Draft2020_12,
    ) {
        Ok(()) => Ok(()),
        Err(rej) => Err(rej.pointers),
    }
}

fn bounded_depth(v: &Value, max: usize) -> bool {
    let mut stack = vec![(v, 1usize)];
    while let Some((node, d)) = stack.pop() {
        if d > max {
            return false;
        }
        match node {
            Value::Object(m) => stack.extend(m.values().map(|x| (x, d + 1))),
            Value::Array(a) => stack.extend(a.iter().map(|x| (x, d + 1))),
            _ => {}
        }
    }
    true
}

// ─── Rendering ────────────────────────────────────────────────────────────

/// The context a definition renders against. `params` is the EFFECTIVE map
/// (defaults applied, references resolved by the server into objects like
/// `{"id": …, "base_url": …, "provider": …}`).
pub struct RenderCtx<'a> {
    pub params: &'a Map<String, Value>,
    pub instance_name: &'a str,
}

/// Render one Value tree: `$param:` typed injection + `{{recipe.*}}` /
/// `{{instance.name}}` interpolation. `Ok(None)` = "this position renders to
/// nothing" (absent optional param) — the parent drops the key/element.
pub fn render_value(v: &Value, ctx: &RenderCtx<'_>) -> Result<Option<Value>, String> {
    match v {
        Value::String(s) => {
            if let Some(rest) = s.strip_prefix("$param:") {
                let (name, field) = match rest.split_once('.') {
                    Some((n, f)) => (n, Some(f)),
                    None => (rest, None),
                };
                if name.is_empty() {
                    return Err("'$param:' names no parameter".into());
                }
                let Some(val) = ctx.params.get(name) else {
                    // Absent optional param ⇒ drop the position. (A missing
                    // REQUIRED param cannot reach here — schema validation
                    // already refused it.)
                    return Ok(None);
                };
                match field {
                    None => match val {
                        // A resolved reference object injects its id when used
                        // bare — the common case ("$param:github_connection"
                        // in a connection_id position).
                        Value::Object(o) if o.contains_key("id") => Ok(Some(o["id"].clone())),
                        other => Ok(Some(other.clone())),
                    },
                    Some(f) => match val {
                        Value::Object(o) => o
                            .get(f)
                            .cloned()
                            .map(Some)
                            .ok_or_else(|| format!("param '{name}' has no field '{f}'")),
                        _ => Err(format!(
                            "param '{name}' is not an object — '.{f}' cannot resolve"
                        )),
                    },
                }
            } else {
                Ok(Some(Value::String(interpolate(s, ctx)?)))
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if let Some(r) = render_value(item, ctx)? {
                    out.push(r);
                }
            }
            Ok(Some(Value::Array(out)))
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, val) in map {
                if let Some(r) = render_value(val, ctx)? {
                    out.insert(k.clone(), r);
                }
            }
            Ok(Some(Value::Object(out)))
        }
        other => Ok(Some(other.clone())),
    }
}

/// `{{recipe.<param>}}` + `{{instance.name}}` interpolation. Any OTHER
/// `{{…}}` is left byte-identical for the run-time renderer; an unknown
/// `recipe.*` key is an error (a silently-empty hole in a prompt is worse).
/// Only string/number/bool params interpolate — an array/object inside a
/// string has no meaningful text form.
fn interpolate(s: &str, ctx: &RenderCtx<'_>) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            // Unclosed braces are the run-time renderer's problem (it errors
            // there); recipe-time passes them through untouched.
            out.push_str(&rest[i..]);
            return Ok(out);
        };
        let key = after[..j].trim();
        if key == "instance.name" {
            out.push_str(ctx.instance_name);
        } else if let Some(pname) = key.strip_prefix("recipe.") {
            let Some(val) = ctx.params.get(pname) else {
                return Err(format!(
                    "template references '{{{{recipe.{pname}}}}}' but no such parameter exists"
                ));
            };
            match val {
                Value::String(v) => out.push_str(v),
                Value::Number(n) => out.push_str(&n.to_string()),
                Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
                Value::Object(o) if o.get("id").and_then(Value::as_str).is_some() => {
                    out.push_str(o["id"].as_str().unwrap())
                }
                _ => {
                    return Err(format!(
                        "parameter '{pname}' is not a string-like value — it cannot interpolate into text"
                    ))
                }
            }
        } else {
            // Run-time namespace (event/schedule vars) — pass through.
            out.push_str(&rest[i..i + 2 + j + 2]);
        }
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Every parameter name a definition references (`$param:name`,
/// `$param:name.field`, `{{recipe.name}}`), for authoring-time typo defense:
/// a reference to an undeclared parameter is dead config and refused at
/// recipe create/append, never discovered at deploy.
pub fn referenced_params(def: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![def];
    while let Some(node) = stack.pop() {
        match node {
            Value::String(s) => {
                if let Some(rest) = s.strip_prefix("$param:") {
                    let name = rest.split('.').next().unwrap_or(rest);
                    if !name.is_empty() {
                        out.insert(name.to_string());
                    }
                } else {
                    let mut rest = s.as_str();
                    while let Some(i) = rest.find("{{") {
                        let after = &rest[i + 2..];
                        let Some(j) = after.find("}}") else { break };
                        if let Some(p) = after[..j].trim().strip_prefix("recipe.") {
                            out.insert(p.to_string());
                        }
                        rest = &after[j + 2..];
                    }
                }
            }
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => stack.extend(m.values()),
            _ => {}
        }
    }
    out
}

// ─── Rendered (post-render, strictly typed) shapes ────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RenderedRecipe {
    pub policy_content: Option<Value>,
    pub agents: Vec<RenderedAgent>,
    pub subscriptions: Vec<RenderedSubscription>,
    pub first_run: Option<RenderedFirstRun>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedAgent {
    pub slot: String,
    pub name: String,
    pub harness: String,
    pub model: Option<String>,
    pub system_prompt: Option<String>,
    pub budgets: Option<Value>,
    pub capability_bundles: Vec<String>,
    /// Rendered requirements array — validated by the deploy engine via
    /// `capability::validate_requirements` after deserialization.
    pub connection_requirements: Value,
    pub workspace: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedSubscription {
    pub slot: String,
    pub agent_slot: String,
    pub kind: String,
    pub name: String,
    pub task_template: Option<String>,
    pub autonomous: bool,
    pub concurrency_policy: String,
    pub connection_id: Option<String>,
    pub repositories: Vec<String>,
    pub events: Option<Vec<String>>,
    pub publish: Option<Vec<String>>,
    pub schedule: Option<RenderedSchedule>,
    pub allow_task_override: bool,
    pub allow_workspace_override: bool,
    pub callback_url: Option<String>,
    pub budgets: Option<Value>,
    pub capabilities: Option<Vec<String>>,
    pub workspace: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedSchedule {
    pub cron: String,
    pub timezone: String,
    pub missed_run_policy: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedFirstRun {
    pub agent_slot: String,
    pub task: String,
    pub autonomous: bool,
}

/// Render a validated definition against effective params. Structural typing
/// of every leaf happens HERE with path-labeled errors; anything needing
/// external context (connections, models, cron future-fire, workspace) is the
/// deploy engine's second pass.
pub fn render_definition(
    def: &RecipeDefinition,
    ctx: &RenderCtx<'_>,
) -> Result<RenderedRecipe, String> {
    let mut agents = Vec::with_capacity(def.agents.len());
    for a in &def.agents {
        let at = |what: &str, e: String| format!("agents[{}].{what}: {e}", a.slot);
        agents.push(RenderedAgent {
            slot: a.slot.clone(),
            name: req_string(&a.name, ctx).map_err(|e| at("name", e))?,
            harness: a.harness.clone(),
            model: opt_string(a.model.as_ref(), ctx).map_err(|e| at("model", e))?,
            system_prompt: opt_string(a.system_prompt.as_ref(), ctx)
                .map_err(|e| at("system_prompt", e))?,
            budgets: opt_object(a.budgets.as_ref(), ctx).map_err(|e| at("budgets", e))?,
            capability_bundles: opt_string_list(a.capability_bundles.as_ref(), ctx)
                .map_err(|e| at("capability_bundles", e))?
                .unwrap_or_default(),
            connection_requirements: match &a.connection_requirements {
                None => Value::Array(vec![]),
                Some(v) => render_value(v, ctx)
                    .map_err(|e| at("connection_requirements", e))?
                    .unwrap_or(Value::Array(vec![])),
            },
            workspace: opt_object(a.workspace.as_ref(), ctx).map_err(|e| at("workspace", e))?,
        });
    }
    let mut subscriptions = Vec::with_capacity(def.subscriptions.len());
    for s in &def.subscriptions {
        let at = |what: &str, e: String| format!("subscriptions[{}].{what}: {e}", s.slot);
        let schedule = match &s.schedule {
            None => None,
            Some(sc) => Some(RenderedSchedule {
                cron: req_string(&sc.cron, ctx).map_err(|e| at("schedule.cron", e))?,
                timezone: opt_string(sc.timezone.as_ref(), ctx)
                    .map_err(|e| at("schedule.timezone", e))?
                    .unwrap_or_else(|| "UTC".to_string()),
                missed_run_policy: opt_string(sc.missed_run_policy.as_ref(), ctx)
                    .map_err(|e| at("schedule.missed_run_policy", e))?
                    .unwrap_or_else(|| "skip".to_string()),
            }),
        };
        subscriptions.push(RenderedSubscription {
            slot: s.slot.clone(),
            agent_slot: s.agent_slot.clone(),
            kind: s.kind.clone(),
            name: req_string(&s.name, ctx).map_err(|e| at("name", e))?,
            task_template: opt_string(s.task_template.as_ref(), ctx)
                .map_err(|e| at("task_template", e))?,
            autonomous: opt_bool(s.autonomous.as_ref(), ctx)
                .map_err(|e| at("autonomous", e))?
                .unwrap_or(false),
            concurrency_policy: opt_string(s.concurrency_policy.as_ref(), ctx)
                .map_err(|e| at("concurrency_policy", e))?
                .unwrap_or_else(|| "allow".to_string()),
            connection_id: opt_string(s.connection.as_ref(), ctx)
                .map_err(|e| at("connection", e))?,
            repositories: opt_string_list(s.repositories.as_ref(), ctx)
                .map_err(|e| at("repositories", e))?
                .unwrap_or_default(),
            events: opt_string_list(s.events.as_ref(), ctx).map_err(|e| at("events", e))?,
            publish: opt_string_list(s.publish.as_ref(), ctx).map_err(|e| at("publish", e))?,
            schedule,
            allow_task_override: opt_bool(s.allow_task_override.as_ref(), ctx)
                .map_err(|e| at("allow_task_override", e))?
                .unwrap_or(false),
            allow_workspace_override: opt_bool(s.allow_workspace_override.as_ref(), ctx)
                .map_err(|e| at("allow_workspace_override", e))?
                .unwrap_or(false),
            callback_url: opt_string(s.callback_url.as_ref(), ctx)
                .map_err(|e| at("callback_url", e))?,
            budgets: opt_object(s.budgets.as_ref(), ctx).map_err(|e| at("budgets", e))?,
            capabilities: opt_string_list(s.capabilities.as_ref(), ctx)
                .map_err(|e| at("capabilities", e))?,
            workspace: opt_object(s.workspace.as_ref(), ctx).map_err(|e| at("workspace", e))?,
        });
    }
    let first_run = match &def.first_run {
        None => None,
        Some(fr) => Some(RenderedFirstRun {
            agent_slot: fr.agent_slot.clone(),
            task: req_string(&fr.task, ctx).map_err(|e| format!("first_run.task: {e}"))?,
            autonomous: opt_bool(fr.autonomous.as_ref(), ctx)
                .map_err(|e| format!("first_run.autonomous: {e}"))?
                .unwrap_or(false),
        }),
    };
    let policy_content = def.policy.as_ref().map(|p| p.content.clone());
    Ok(RenderedRecipe {
        policy_content,
        agents,
        subscriptions,
        first_run,
    })
}

// Typed extraction helpers — each renders first, then coerces, so "$param:x"
// markers work in every position.

fn req_string(v: &Value, ctx: &RenderCtx<'_>) -> Result<String, String> {
    match render_value(v, ctx)? {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s),
        Some(Value::String(_)) => Err("renders to an empty string".into()),
        Some(other) => Err(format!("must render to a string (got {})", kind_of(&other))),
        None => Err("renders to nothing (absent parameter) but is required".into()),
    }
}

fn opt_string(v: Option<&Value>, ctx: &RenderCtx<'_>) -> Result<Option<String>, String> {
    match v {
        None => Ok(None),
        Some(v) => match render_value(v, ctx)? {
            None => Ok(None),
            Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(other) => Err(format!("must render to a string (got {})", kind_of(&other))),
        },
    }
}

fn opt_bool(v: Option<&Value>, ctx: &RenderCtx<'_>) -> Result<Option<bool>, String> {
    match v {
        None => Ok(None),
        Some(v) => match render_value(v, ctx)? {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(b)),
            Some(other) => Err(format!(
                "must render to a boolean (got {})",
                kind_of(&other)
            )),
        },
    }
}

fn opt_object(v: Option<&Value>, ctx: &RenderCtx<'_>) -> Result<Option<Value>, String> {
    match v {
        None => Ok(None),
        Some(v) => match render_value(v, ctx)? {
            None => Ok(None),
            Some(o @ Value::Object(_)) => Ok(Some(o)),
            Some(other) => Err(format!(
                "must render to an object (got {})",
                kind_of(&other)
            )),
        },
    }
}

fn opt_string_list(v: Option<&Value>, ctx: &RenderCtx<'_>) -> Result<Option<Vec<String>>, String> {
    match v {
        None => Ok(None),
        Some(v) => match render_value(v, ctx)? {
            None => Ok(None),
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    match item {
                        Value::String(s) => out.push(s.clone()),
                        other => {
                            return Err(format!(
                                "element {i} must be a string (got {})",
                                kind_of(other)
                            ))
                        }
                    }
                }
                Ok(Some(out))
            }
            Some(other) => Err(format!(
                "must render to an array of strings (got {})",
                kind_of(&other)
            )),
        },
    }
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with<'a>(params: &'a Map<String, Value>) -> RenderCtx<'a> {
        RenderCtx {
            params,
            instance_name: "acme pr review",
        }
    }

    fn params(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    // ── definition validation ──

    fn minimal_def(extra: Value) -> Value {
        let mut base = json!({
            "schema": 1,
            "agents": [{ "slot": "main", "name": "{{instance.name}}", "harness": "claude-agent-sdk" }]
        });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        base
    }

    #[test]
    fn definition_parses_and_validates() {
        RecipeDefinition::parse(&minimal_def(json!({}))).unwrap();
    }

    #[test]
    fn definition_refuses_unknown_fields() {
        let mut d = minimal_def(json!({}));
        d.as_object_mut()
            .unwrap()
            .insert("surprise".into(), json!(1));
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("does not parse"));
    }

    #[test]
    fn definition_refuses_newer_schema() {
        let d = minimal_def(json!({ "schema": 2 }));
        // Overwrite schema key (extend put 2 in already via minimal_def merge).
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("not supported"));
    }

    #[test]
    fn definition_refuses_duplicate_and_bad_slots() {
        let d = json!({
            "schema": 1,
            "agents": [
                { "slot": "a", "name": "x", "harness": "claude-agent-sdk" },
                { "slot": "a", "name": "y", "harness": "claude-agent-sdk" }
            ]
        });
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("duplicate agent slot"));
        let d = json!({
            "schema": 1,
            "agents": [{ "slot": "Bad_Slot", "name": "x", "harness": "claude-agent-sdk" }]
        });
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("[a-z0-9-]"));
    }

    #[test]
    fn definition_cross_checks_subscription_shape() {
        let base = |sub: Value| {
            json!({
                "schema": 1,
                "agents": [{ "slot": "main", "name": "x", "harness": "claude-agent-sdk" }],
                "subscriptions": [sub]
            })
        };
        let err = RecipeDefinition::parse(&base(
            json!({ "slot": "s", "agent_slot": "ghost", "kind": "api", "name": "n" }),
        ))
        .unwrap_err();
        assert!(err.contains("unknown agent slot 'ghost'"));
        let err = RecipeDefinition::parse(&base(
            json!({ "slot": "s", "agent_slot": "main", "kind": "cron", "name": "n" }),
        ))
        .unwrap_err();
        assert!(err.contains("kind must be one of"));
        let err = RecipeDefinition::parse(&base(
            json!({ "slot": "s", "agent_slot": "main", "kind": "schedule", "name": "n" }),
        ))
        .unwrap_err();
        assert!(err.contains("has no schedule"));
        let err = RecipeDefinition::parse(&base(
            json!({ "slot": "s", "agent_slot": "main", "kind": "event", "name": "n" }),
        ))
        .unwrap_err();
        assert!(err.contains("has no connection"));
        let err = RecipeDefinition::parse(&base(json!({
            "slot": "s", "agent_slot": "main", "kind": "api", "name": "n",
            "schedule": { "cron": "0 9 * * 1" }
        })))
        .unwrap_err();
        assert!(err.contains("carries a schedule"));
    }

    #[test]
    fn definition_validates_embedded_policy() {
        let d = minimal_def(json!({ "policy": { "content": { "nonsense": true } } }));
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("policy content does not parse"));
    }

    #[test]
    fn definition_first_run_slot_checked() {
        let d = minimal_def(json!({ "first_run": { "agent_slot": "ghost", "task": "t" } }));
        assert!(RecipeDefinition::parse(&d)
            .unwrap_err()
            .contains("first_run names unknown agent slot"));
    }

    // ── param specs ──

    fn schema_with(props: Value, required: Value) -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": required,
            "properties": props
        })
    }

    #[test]
    fn param_specs_walks_widgets_and_order() {
        let mut schema = schema_with(
            json!({
                "repo": { "type": "string", "title": "Repository", "x-fluidbox": { "widget": "text" } },
                "conn": { "type": "string", "x-fluidbox": { "widget": "connection", "provider": "github" } },
                "count": { "type": "integer", "default": 3 },
                "mode": { "type": "string", "enum": ["a", "b"] }
            }),
            json!(["conn"]),
        );
        schema
            .as_object_mut()
            .unwrap()
            .insert("x-fluidbox-ui".into(), json!({ "order": ["conn", "repo"] }));
        let specs = param_specs(&schema).unwrap();
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["conn", "repo", "count", "mode"]);
        assert!(specs[0].required);
        assert_eq!(
            specs[0].widget,
            ParamWidget::Connection {
                provider: Some("github".into()),
                mcp: false
            }
        );
        assert_eq!(specs[2].default, Some(json!(3)));
        assert_eq!(specs[3].widget, ParamWidget::Select);
    }

    #[test]
    fn param_specs_refuses_secret_widgets_and_unknown() {
        let schema = schema_with(
            json!({ "k": { "type": "string", "x-fluidbox": { "widget": "secret" } } }),
            json!([]),
        );
        assert!(param_specs(&schema)
            .unwrap_err()
            .contains("never recipe parameters"));
        let schema = schema_with(
            json!({ "k": { "type": "string", "x-fluidbox": { "widget": "wat" } } }),
            json!([]),
        );
        assert!(param_specs(&schema).unwrap_err().contains("unknown widget"));
    }

    #[test]
    fn param_specs_requires_strict_object_schema() {
        assert!(param_specs(&json!({ "type": "object", "properties": {} }))
            .unwrap_err()
            .contains("additionalProperties"));
        assert!(param_specs(&json!({
            "type": "object", "additionalProperties": false
        }))
        .unwrap_err()
        .contains("properties"));
    }

    #[test]
    fn param_specs_checks_connection_tools_target() {
        let schema = schema_with(
            json!({ "tools": { "type": "array", "items": {"type": "string"},
                     "x-fluidbox": { "widget": "connection_tools", "connection_param": "nope" } } }),
            json!([]),
        );
        assert!(param_specs(&schema)
            .unwrap_err()
            .contains("not a declared param"));
    }

    // ── validation + defaults ──

    #[test]
    fn defaults_fill_then_validate() {
        let schema = schema_with(
            json!({
                "events": { "type": "array", "items": { "enum": ["opened", "reopened"] },
                            "default": ["opened"] },
                "repo": { "type": "string" }
            }),
            json!(["repo"]),
        );
        let effective = apply_defaults(&schema, &params(json!({ "repo": "acme/site" })));
        assert_eq!(effective["events"], json!(["opened"]));
        validate_params(&schema, &effective).unwrap();
        let bad = apply_defaults(&schema, &params(json!({ "repo": 7 })));
        assert!(!validate_params(&schema, &bad).unwrap_err().is_empty());
        // Unknown params are refused by additionalProperties:false.
        let unknown = apply_defaults(&schema, &params(json!({ "repo": "a/b", "x": 1 })));
        assert!(!validate_params(&schema, &unknown).unwrap_err().is_empty());
    }

    // ── rendering ──

    #[test]
    fn render_typed_injection_and_interpolation() {
        let p = params(json!({
            "repos": ["acme/site", "acme/api"],
            "model": "claude-haiku-4-5",
            "conn": { "id": "11111111-1111-7111-8111-111111111111", "base_url": "https://mcp.example/x", "provider": "github" },
            "n": 3
        }));
        let ctx = ctx_with(&p);
        let v = json!({
            "repositories": "$param:repos",
            "connection": "$param:conn",
            "url": "$param:conn.base_url",
            "prompt": "Use {{recipe.model}} on {{repository}} for {{instance.name}} ({{recipe.n}} passes)"
        });
        let out = render_value(&v, &ctx).unwrap().unwrap();
        assert_eq!(out["repositories"], json!(["acme/site", "acme/api"]));
        assert_eq!(
            out["connection"],
            json!("11111111-1111-7111-8111-111111111111")
        );
        assert_eq!(out["url"], json!("https://mcp.example/x"));
        // {{repository}} is runtime-namespace: untouched.
        assert_eq!(
            out["prompt"],
            json!("Use claude-haiku-4-5 on {{repository}} for acme pr review (3 passes)")
        );
    }

    #[test]
    fn render_drops_absent_optional_params() {
        let p = params(json!({ "present": "x" }));
        let ctx = ctx_with(&p);
        let v = json!({ "keep": "$param:present", "gone": "$param:absent",
                        "list": ["$param:absent", "$param:present"] });
        let out = render_value(&v, &ctx).unwrap().unwrap();
        assert_eq!(out, json!({ "keep": "x", "list": ["x"] }));
    }

    #[test]
    fn render_errors_name_problems() {
        let p = params(json!({ "s": "x", "arr": [1] }));
        let ctx = ctx_with(&p);
        assert!(interpolate("hello {{recipe.ghost}}", &ctx)
            .unwrap_err()
            .contains("no such parameter"));
        assert!(render_value(&json!("$param:s.field"), &ctx)
            .unwrap_err()
            .contains("not an object"));
        // Array param inside a text template is refused.
        assert!(interpolate("x {{recipe.arr}}", &ctx)
            .unwrap_err()
            .contains("cannot interpolate"));
    }

    #[test]
    fn render_definition_end_to_end() {
        let def = RecipeDefinition::parse(&json!({
            "schema": 1,
            "agents": [{
                "slot": "reviewer",
                "name": "{{instance.name}} reviewer",
                "harness": "claude-agent-sdk",
                "model": "$param:model",
                "system_prompt": "You review code.",
                "budgets": { "max_cost_usd": 1.5 }
            }],
            "subscriptions": [{
                "slot": "on-pr",
                "agent_slot": "reviewer",
                "kind": "event",
                "name": "{{instance.name}} — on PR",
                "task_template": "Review PR #{{pr_number}} of {{repository}}.",
                "autonomous": true,
                "connection": "$param:gh",
                "repositories": "$param:repos",
                "events": "$param:events",
                "publish": ["check"]
            }],
            "first_run": null
        }))
        .unwrap();
        let p = params(json!({
            "model": "claude-haiku-4-5",
            "gh": { "id": "22222222-2222-7222-8222-222222222222", "provider": "github" },
            "repos": ["acme/site"],
            "events": ["opened", "reopened"]
        }));
        let ctx = ctx_with(&p);
        let r = render_definition(&def, &ctx).unwrap();
        assert_eq!(r.agents[0].name, "acme pr review reviewer");
        assert_eq!(r.agents[0].model.as_deref(), Some("claude-haiku-4-5"));
        let sub = &r.subscriptions[0];
        assert_eq!(
            sub.connection_id.as_deref(),
            Some("22222222-2222-7222-8222-222222222222")
        );
        assert_eq!(sub.repositories, vec!["acme/site"]);
        assert_eq!(
            sub.events,
            Some(vec!["opened".to_string(), "reopened".to_string()])
        );
        assert!(sub.autonomous);
        assert_eq!(
            sub.task_template.as_deref(),
            Some("Review PR #{{pr_number}} of {{repository}}.")
        );
    }

    #[test]
    fn render_definition_labels_paths() {
        let def = RecipeDefinition::parse(&json!({
            "schema": 1,
            "agents": [{ "slot": "a", "name": "$param:missing_required",
                          "harness": "claude-agent-sdk" }]
        }))
        .unwrap();
        let p = params(json!({}));
        let err = render_definition(&def, &ctx_with(&p)).unwrap_err();
        assert!(err.starts_with("agents[a].name:"), "{err}");
    }
}
