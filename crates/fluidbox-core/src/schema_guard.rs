//! Frozen-schema argument enforcement (Gap 12, invariants 13/17; design
//! `:1344-1356`, plan E9).
//!
//! A brokered tool's `inputSchema` is UNTRUSTED photographed data (invariant
//! 13). This module lets the permission gate (a) screen a frozen schema before
//! it is ever compiled, and (b) validate a tool call's arguments against that
//! frozen schema under the dialect the snapshot's MCP protocol version selects —
//! all WITHOUT any external `$ref` resolution and with hard depth/size bounds so
//! a hostile schema or a hostile argument blob can neither escape nor exhaust
//! the control plane.
//!
//! The three defenses against a hostile schema, none sufficient alone:
//! 1. [`guard_schema`] rejects a schema that is too large, too deeply nested, or
//!    carries a non-local `$ref`/`$dynamicRef` — BEFORE compilation.
//! 2. Compilation forces the dialect and installs a deny-everything retriever, so
//!    even a `$ref` that slipped the guard cannot trigger an outbound fetch.
//! 3. [`validate_instance`] pre-bounds the argument blob (size + depth) before
//!    handing it to the compiled validator.

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use jsonschema::Validator;

/// Serialized frozen-schema ceiling (design `:1351`). A schema over this is
/// un-callable — the gate denies (`source=schema`).
const MAX_SCHEMA_BYTES: usize = 256 * 1024;
/// Frozen-schema nesting ceiling (design `:1351`), checked ITERATIVELY.
const MAX_SCHEMA_DEPTH: usize = 32;
/// Serialized argument-blob ceiling (design `:1352`).
const MAX_ARGS_BYTES: usize = 1024 * 1024;
/// Argument-blob nesting ceiling (design `:1352`), checked ITERATIVELY.
const MAX_ARGS_DEPTH: usize = 64;
/// Cap on the JSON-pointer paths reported for a rejected argument blob — bounded
/// so a hostile schema cannot balloon the gate's deny message.
const MAX_POINTERS: usize = 8;
/// Default compiled-validator LRU capacity (plan E9).
pub const DEFAULT_CACHE_CAP: usize = 256;

/// A single, value-free marker used when the argument blob itself blows the
/// pre-guard bounds (size/depth) — there is no meaningful JSON-pointer path for
/// "the whole blob is too big", and echoing any of it would leak arguments.
const ARGS_BOUND_MARKER: &str = "(arguments exceed the size or nesting bound)";

/// The JSON Schema dialect a frozen `inputSchema` is compiled under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaDialect {
    Draft2020_12,
    Draft7,
}

/// Pick the dialect from the snapshot's negotiated MCP protocol version
/// (SEP-1613; design `:1353`, plan E9):
/// - `"2025-11-25"` ⇒ JSON Schema **2020-12** (the revision that pins it);
/// - any OTHER explicit version ⇒ **draft-07** (the `2025-06-18`-and-earlier
///   lineage);
/// - ABSENT (`None`) ⇒ **2020-12**, the SEP-1613 default. Legacy capability
///   bundles and any surface frozen before `protocol_version` existed take this
///   path.
pub fn dialect_for(protocol_version: Option<&str>) -> SchemaDialect {
    match protocol_version {
        Some("2025-11-25") => SchemaDialect::Draft2020_12,
        Some(_) => SchemaDialect::Draft7,
        None => SchemaDialect::Draft2020_12,
    }
}

/// Screen a frozen `inputSchema` before it is EVER compiled (design `:1351`).
/// The schema is untrusted, so a violation makes the tool un-callable (the gate
/// denies, `source=schema`). Reasons are STATIC — the schema is never echoed.
///
/// Rejects, in ONE iterative traversal (an explicit stack — never recurses, so a
/// pathologically deep tree returns `Err` instead of overflowing the stack):
/// - nesting deeper than [`MAX_SCHEMA_DEPTH`];
/// - a `$ref` or `$dynamicRef` whose STRING value does not start with `#`
///   (external references are refused; a non-string value under those keys is a
///   property literally named `$ref`, not a reference, and is left alone).
///
/// Then, once depth is known bounded, a serialized-size check ≤ [`MAX_SCHEMA_BYTES`].
pub fn guard_schema(schema: &Value) -> Result<(), String> {
    // ONE iterative DFS: bound depth AND screen every $ref/$dynamicRef. The
    // depth screen runs BEFORE any serialization, so a pathologically deep tree
    // is rejected here and the size check below never recurses into it.
    let mut stack: Vec<(&Value, usize)> = vec![(schema, 1)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(format!(
                "frozen schema nests deeper than {MAX_SCHEMA_DEPTH} levels"
            ));
        }
        match node {
            Value::Object(map) => {
                for (key, val) in map {
                    if (key == "$ref" || key == "$dynamicRef") && val.is_string() {
                        // A STRING value under $ref/$dynamicRef IS a reference —
                        // it must be a local fragment. A non-string value is a
                        // property literally named "$ref", not a reference.
                        let local = val.as_str().map(|s| s.starts_with('#')).unwrap_or(false);
                        if !local {
                            return Err(format!(
                                "frozen schema carries a non-local {key} — external references are refused"
                            ));
                        }
                    }
                    stack.push((val, depth + 1));
                }
            }
            Value::Array(arr) => {
                for val in arr {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }
    // Size: safe to serialize now — depth is bounded, so serde_json's recursive
    // serializer cannot overflow.
    let len = serde_json::to_vec(schema)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if len > MAX_SCHEMA_BYTES {
        return Err(format!(
            "frozen schema is larger than {MAX_SCHEMA_BYTES} bytes serialized"
        ));
    }
    Ok(())
}

/// Iteratively confirm `value` nests no deeper than `max_depth` (explicit stack,
/// never recurses). The pre-guard for both frozen schemas and argument blobs.
fn within_depth(value: &Value, max_depth: usize) -> bool {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 1)];
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            return false;
        }
        match node {
            Value::Object(map) => {
                for (_, val) in map {
                    stack.push((val, depth + 1));
                }
            }
            Value::Array(arr) => {
                for val in arr {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }
    true
}

/// The JSON-pointer paths at which an argument blob failed its frozen schema.
/// PATHS ONLY — argument VALUES are secrets-adjacent and never appear here or in
/// the gate's ledger message.
#[derive(Debug, Clone, PartialEq)]
pub struct ArgsRejection {
    pub pointers: Vec<String>,
}

impl ArgsRejection {
    /// A bounded, value-free one-line summary for the gate deny message + ledger
    /// reason: the JSON-pointer paths joined and truncated. Bounded by BYTES (on a
    /// char boundary) — a pointer echoes attacker-influenced KEY names (never
    /// values), which may be multi-byte — so the whole gate message stays well
    /// under the ledger's 512-byte budget.
    pub fn summary(&self) -> String {
        const MAX_SUMMARY_BYTES: usize = 400;
        let joined = self.pointers.join(", ");
        if joined.len() <= MAX_SUMMARY_BYTES {
            return joined;
        }
        let mut end = MAX_SUMMARY_BYTES;
        while end > 0 && !joined.is_char_boundary(end) {
            end -= 1;
        }
        joined[..end].to_string()
    }
}

/// Validate `args` against a pre-compiled frozen-schema `validator`. Pre-guards
/// the argument blob (untrusted from the model/sandbox) to [`MAX_ARGS_BYTES`] /
/// [`MAX_ARGS_DEPTH`] first, then collects up to [`MAX_POINTERS`] distinct
/// failing JSON-pointer paths. `Ok(())` = the args satisfy the schema.
pub fn validate_instance(validator: &Validator, args: &Value) -> Result<(), ArgsRejection> {
    // Pre-guard the untrusted argument blob: depth FIRST (iterative — a deep
    // blob is rejected here, never overflowing the validator's recursion), then
    // size once depth is bounded.
    if !within_depth(args, MAX_ARGS_DEPTH)
        || serde_json::to_vec(args)
            .map(|v| v.len())
            .unwrap_or(usize::MAX)
            > MAX_ARGS_BYTES
    {
        return Err(ArgsRejection {
            pointers: vec![ARGS_BOUND_MARKER.to_string()],
        });
    }
    // Collect up to MAX_POINTERS distinct failing JSON-pointer PATHS. The empty
    // (root) path renders as "(root)"; a VALUE never appears.
    let mut pointers: Vec<String> = Vec::new();
    for err in validator.iter_errors(args) {
        let path = err.instance_path().to_string();
        let path = if path.is_empty() {
            "(root)".to_string()
        } else {
            path
        };
        if !pointers.contains(&path) {
            pointers.push(path);
            if pointers.len() >= MAX_POINTERS {
                break;
            }
        }
    }
    if pointers.is_empty() {
        Ok(())
    } else {
        Err(ArgsRejection { pointers })
    }
}

/// Compile `schema` under a FORCED `dialect` with external `$ref` resolution
/// refused, then validate `args`. Convenience wrapper over
/// [`validate_instance`]; the gate uses [`SchemaCache`] instead to reuse compiled
/// validators. A schema that fails to compile is reported as an argument
/// rejection carrying a single non-value marker (the gate never reaches this —
/// it compiles via the cache, which maps a compile error to the distinct
/// schema-invalid deny — so this only guards direct callers/tests).
pub fn validate_args(
    schema: &Value,
    args: &Value,
    dialect: SchemaDialect,
) -> Result<(), ArgsRejection> {
    let validator = compile(schema, dialect).map_err(|_| ArgsRejection {
        pointers: vec!["(frozen schema did not compile)".to_string()],
    })?;
    validate_instance(&validator, args)
}

/// A bounded LRU of compiled frozen-schema validators, keyed
/// `(tools_digest, tool)` (plan E9). The digest identifies the run's frozen tool
/// surface, so a `/tools/refresh` (new digest) never reuses a stale compilation.
pub struct SchemaCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    cap: usize,
    map: HashMap<(String, String), CacheEntry>,
    /// Front = least-recently-used, back = most-recent.
    order: VecDeque<(String, String)>,
}

struct CacheEntry {
    dialect: SchemaDialect,
    validator: Arc<Validator>,
}

impl SchemaCache {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                cap: cap.max(1),
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Return the compiled validator for `(tools_digest, tool)`, compiling +
    /// caching on a miss. `Err` = the frozen schema did not compile (the gate
    /// maps this to the schema-invalid deny). STUB: recompiles every call.
    pub fn get_or_compile(
        &self,
        tools_digest: &str,
        tool: &str,
        schema: &Value,
        dialect: SchemaDialect,
    ) -> Result<Arc<Validator>, String> {
        let key = (tools_digest.to_string(), tool.to_string());
        // Fast path: a hit whose stored dialect matches. The dialect is checked
        // because it is NOT part of tools_digest — two surfaces could share a
        // digest yet negotiate different protocol versions; a mismatch recompiles
        // rather than serve the wrong dialect's validator.
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(entry) = inner.map.get(&key) {
                if entry.dialect == dialect {
                    let validator = entry.validator.clone();
                    inner.touch(&key);
                    return Ok(validator);
                }
            }
        }
        // Compile OUTSIDE the lock (compilation is the slow part; it must not
        // block other keys).
        let validator = Arc::new(compile(schema, dialect)?);
        let mut inner = self.inner.lock().unwrap();
        inner.insert(
            key,
            CacheEntry {
                dialect,
                validator: validator.clone(),
            },
        );
        Ok(validator)
    }
}

impl CacheInner {
    /// Move `key` to the most-recently-used end.
    fn touch(&mut self, key: &(String, String)) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            if let Some(k) = self.order.remove(pos) {
                self.order.push_back(k);
            }
        }
    }

    /// Insert (or replace) `key`, evicting the least-recently-used entries past
    /// the capacity.
    fn insert(&mut self, key: (String, String), entry: CacheEntry) {
        if self.map.insert(key.clone(), entry).is_some() {
            self.touch(&key);
        } else {
            self.order.push_back(key);
            while self.order.len() > self.cap {
                if let Some(evicted) = self.order.pop_front() {
                    self.map.remove(&evicted);
                }
            }
        }
    }
}

impl Default for SchemaCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_CAP)
    }
}

/// Compile one frozen schema under a forced dialect with a deny-everything
/// retriever. STUB body still real (tests need a working compile).
fn compile(schema: &Value, dialect: SchemaDialect) -> Result<Validator, String> {
    let draft = match dialect {
        SchemaDialect::Draft2020_12 => jsonschema::Draft::Draft202012,
        SchemaDialect::Draft7 => jsonschema::Draft::Draft7,
    };
    jsonschema::options()
        .with_draft(draft)
        .with_retriever(DenyRetriever)
        .should_validate_formats(false)
        .build(schema)
        .map_err(|e| e.to_string().chars().take(200).collect())
}

/// A retriever that refuses every external reference — belt on top of
/// [`guard_schema`]'s `$ref` screen (plan E9). With the crate's resolve-http /
/// resolve-file features OFF this is also the built-in default, but installing it
/// explicitly makes the refusal a property of THIS code, not of a feature flag.
struct DenyRetriever;

impl jsonschema::Retrieve for DenyRetriever {
    fn retrieve(
        &self,
        _uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema references are refused".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── dialect_for matrix ─────────────────────────────────────────────────
    #[test]
    fn dialect_matrix() {
        assert_eq!(dialect_for(Some("2025-11-25")), SchemaDialect::Draft2020_12);
        assert_eq!(dialect_for(Some("2025-06-18")), SchemaDialect::Draft7);
        assert_eq!(dialect_for(Some("2024-11-05")), SchemaDialect::Draft7);
        assert_eq!(dialect_for(Some("anything-else")), SchemaDialect::Draft7);
        // Absent ⇒ 2020-12 (SEP-1613 default; legacy surfaces/bundles).
        assert_eq!(dialect_for(None), SchemaDialect::Draft2020_12);
    }

    // ── guard_schema ────────────────────────────────────────────────────────
    #[test]
    fn guard_allows_ordinary_and_local_refs() {
        guard_schema(&json!({"type": "object"})).unwrap();
        // A local fragment ref is fine (# / #/$defs/... / #/definitions/...).
        guard_schema(&json!({
            "type": "object",
            "properties": {"x": {"$ref": "#/definitions/x"}},
            "definitions": {"x": {"type": "string"}}
        }))
        .unwrap();
        guard_schema(&json!({"$dynamicRef": "#meta"})).unwrap();
        // A property literally NAMED "$ref" (object value, not a reference) is
        // left alone — no false positive.
        guard_schema(&json!({"properties": {"$ref": {"type": "string"}}})).unwrap();
    }

    #[test]
    fn guard_rejects_remote_and_file_refs() {
        assert!(guard_schema(&json!({"$ref": "https://evil.test/schema.json"})).is_err());
        assert!(guard_schema(&json!({"$ref": "file:///etc/passwd"})).is_err());
        // Nested, and a bare relative ref (no #) is also non-local.
        assert!(guard_schema(&json!({
            "properties": {"a": {"items": {"$ref": "other.json#/x"}}}
        }))
        .is_err());
        // A non-local $dynamicRef is refused the same way.
        assert!(guard_schema(&json!({"$dynamicRef": "https://evil.test#m"})).is_err());
    }

    #[test]
    fn guard_rejects_size_bomb() {
        // A shallow object whose serialized form exceeds 256 KiB.
        let big: String = "x".repeat(300 * 1024);
        let schema = json!({"type": "object", "description": big});
        assert!(guard_schema(&schema).is_err());
    }

    #[test]
    fn guard_rejects_depth_bomb_and_survives_10k_without_stack_overflow() {
        // 40 levels of nested objects: over the 32 cap → Err (not a crash).
        let mut v = json!({"type": "string"});
        for _ in 0..40 {
            v = json!({"type": "object", "properties": {"n": v}});
        }
        assert!(guard_schema(&v).is_err());

        // 10_000-deep ARRAY: the iterative traversal must return Err, never
        // overflow the stack (THIS is the depth-bomb test). guard_schema returns
        // Err after ~33 shallow iterations. Build with `Value::Array(vec![a])` —
        // a plain MOVE per level (never `json!([a])`, which re-serializes `a`
        // recursively and would overflow during CONSTRUCTION). `mem::forget` then
        // skips serde_json's OWN recursive `Value::Drop` (unrelated to the guard),
        // which would itself overflow when a 10k-deep Value goes out of scope.
        let mut a = Value::from(0);
        for _ in 0..10_000 {
            a = Value::Array(vec![a]);
        }
        assert!(
            guard_schema(&a).is_err(),
            "a 10k-deep tree must be rejected iteratively, not crash"
        );
        std::mem::forget(a);
    }

    // ── validate_args: both dialects, valid + invalid ───────────────────────
    #[test]
    fn validate_args_type_and_required_both_dialects() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}, "n": {"type": "integer"}},
            "required": ["name"]
        });
        for dialect in [SchemaDialect::Draft2020_12, SchemaDialect::Draft7] {
            // Valid.
            validate_args(&schema, &json!({"name": "ok", "n": 3}), dialect).unwrap();
            // Missing required + wrong type.
            assert!(validate_args(&schema, &json!({"n": "notint"}), dialect).is_err());
        }
    }

    // ── dialect divergence: the SAME args must resolve DIFFERENTLY per dialect,
    //    and the outcome must be DRIVEN BY `dialect_for` (so a break in dialect
    //    selection — in EITHER direction — flips an assertion). jsonschema-rs
    //    keeps `dependencies` enforced under 2020-12 (back-compat), so there is
    //    no clean pass-2020/fail-draft7 keyword; instead each fixture PINS BOTH
    //    dialect outcomes, which is what fails if selection collapses to one draft.
    #[test]
    fn dialect_divergence_prefix_items_driven_by_dialect_for() {
        // `prefixItems` is a 2020-12 tuple assertion; draft-07 ignores the keyword.
        let schema = json!({"type": "array", "prefixItems": [{"type": "string"}]});
        let args = json!([42]); // item 0 is a number, not a string
                                // Direct dialect: pin BOTH outcomes for the identical args.
        assert!(
            validate_args(&schema, &args, SchemaDialect::Draft2020_12).is_err(),
            "2020-12 must enforce prefixItems and reject a numeric item 0"
        );
        validate_args(&schema, &args, SchemaDialect::Draft7)
            .expect("draft-07 ignores prefixItems, so the same args pass");
        // Through dialect_for: the protocol version drives which outcome wins.
        assert!(
            validate_args(&schema, &args, dialect_for(Some("2025-11-25"))).is_err(),
            "2025-11-25 → 2020-12 → reject"
        );
        validate_args(&schema, &args, dialect_for(Some("2025-06-18")))
            .expect("2025-06-18 → draft-07 → accept");
        assert!(
            validate_args(&schema, &args, dialect_for(None)).is_err(),
            "None → 2020-12 default → reject"
        );
    }

    #[test]
    fn dialect_divergence_dependent_required_driven_by_dialect_for() {
        // `dependentRequired` is a 2020-12 assertion; draft-07 ignores it. A
        // second, independent keyword so the divergence isn't a prefixItems fluke.
        let schema = json!({"type": "object", "dependentRequired": {"a": ["b"]}});
        let args = json!({"a": 1}); // has "a" but not the dependent "b"
        assert!(
            validate_args(&schema, &args, dialect_for(Some("2025-11-25"))).is_err(),
            "2020-12 must require b when a is present"
        );
        validate_args(&schema, &args, dialect_for(Some("2025-06-18")))
            .expect("draft-07 ignores dependentRequired, so the same args pass");
    }

    // ── pointer output: PATHS not VALUES, ≤8 cap ────────────────────────────
    #[test]
    fn rejection_reports_paths_not_values() {
        // `secret` must be an integer; the args pass a STRING — so it fails, and
        // the value (the secret string) must never surface in the pointer/summary.
        let schema = json!({
            "type": "object",
            "properties": {"secret": {"type": "integer"}}
        });
        let secret = "hunter2-super-secret";
        let rej = validate_args(
            &schema,
            &json!({"secret": secret}),
            SchemaDialect::Draft2020_12,
        )
        .unwrap_err();
        // A pointer to the failing member — never the value.
        assert!(rej.pointers.iter().any(|p| p.contains("secret")));
        let summary = rej.summary();
        assert!(
            !summary.contains(secret),
            "the secret VALUE must never appear in the rejection summary: {summary}"
        );
    }

    #[test]
    fn rejection_pointer_list_is_capped_at_8() {
        // A schema where MANY members fail at once (all wrong type).
        let mut props = serde_json::Map::new();
        for i in 0..20 {
            props.insert(format!("f{i}"), json!({"type": "string"}));
        }
        let schema = json!({"type": "object", "properties": props});
        let mut args = serde_json::Map::new();
        for i in 0..20 {
            args.insert(format!("f{i}"), json!(i)); // all integers, all fail
        }
        let rej =
            validate_args(&schema, &Value::Object(args), SchemaDialect::Draft2020_12).unwrap_err();
        assert!(
            rej.pointers.len() <= MAX_POINTERS,
            "got {}",
            rej.pointers.len()
        );
        assert!(!rej.pointers.is_empty());
    }

    #[test]
    fn summary_is_byte_bounded_on_a_char_boundary() {
        // A pathological rejection whose joined pointers include long, multi-byte
        // key names must still produce a summary bounded by BYTES (≤400) and valid
        // UTF-8 (never split mid-char) — so the gate deny message stays under the
        // ledger budget.
        let rej = ArgsRejection {
            pointers: (0..8)
                .map(|i| format!("/{}", "é".repeat(200 + i)))
                .collect(),
        };
        let s = rej.summary();
        assert!(s.len() <= 400, "summary is {} bytes", s.len());
        // Round-tripping proves it did not split a multi-byte char.
        assert_eq!(s, String::from_utf8(s.clone().into_bytes()).unwrap());
    }

    #[test]
    fn oversized_and_too_deep_args_are_rejected() {
        let schema = json!({"type": "object"});
        // Size bomb: a >1 MiB string argument.
        let big = json!({"blob": "z".repeat(1024 * 1024 + 16)});
        assert!(validate_args(&schema, &big, SchemaDialect::Draft2020_12).is_err());
        // Depth bomb: 10k-deep args → iterative pre-guard rejects, no crash.
        // Build by MOVE, forget on the way out — see the guard depth-bomb test.
        let mut a = Value::from(0);
        for _ in 0..10_000 {
            a = Value::Array(vec![a]);
        }
        assert!(validate_args(&schema, &a, SchemaDialect::Draft2020_12).is_err());
        std::mem::forget(a);
    }

    // ── SchemaCache LRU ──────────────────────────────────────────────────────
    #[test]
    fn cache_hit_returns_same_arc() {
        let cache = SchemaCache::new(8);
        let schema = json!({"type": "object"});
        let a = cache
            .get_or_compile("digestA", "mcp__s__t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        let b = cache
            .get_or_compile("digestA", "mcp__s__t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b), "a cache hit must return the same Arc");
    }

    #[test]
    fn cache_distinct_digests_are_distinct_entries() {
        let cache = SchemaCache::new(8);
        let schema = json!({"type": "object"});
        let a = cache
            .get_or_compile("digestA", "mcp__s__t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        let b = cache
            .get_or_compile("digestB", "mcp__s__t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "distinct digests must not share an entry"
        );
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let cache = SchemaCache::new(2);
        let schema = json!({"type": "object"});
        let first = cache
            .get_or_compile("d0", "t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        cache
            .get_or_compile("d1", "t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        cache
            .get_or_compile("d2", "t", &schema, SchemaDialect::Draft2020_12)
            .unwrap(); // evicts d0 (LRU)
                       // d0 recompiles → a fresh Arc (proves it was evicted).
        let first_again = cache
            .get_or_compile("d0", "t", &schema, SchemaDialect::Draft2020_12)
            .unwrap();
        assert!(
            !Arc::ptr_eq(&first, &first_again),
            "the LRU entry must have been evicted at capacity"
        );
    }

    #[test]
    fn cache_maps_uncompilable_schema_to_err() {
        let cache = SchemaCache::new(4);
        // `type` must be a string/array of strings — a number is not a schema.
        let bad = json!({"type": 123});
        assert!(cache
            .get_or_compile("dbad", "t", &bad, SchemaDialect::Draft2020_12)
            .is_err());
    }
}
