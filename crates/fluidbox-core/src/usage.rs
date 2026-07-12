use serde::{Deserialize, Serialize};

/// Token usage for one model response (cache-aware, dialect-neutral).
/// `input_tokens` counts UNCACHED input only; cached reads ride
/// `cache_read_tokens` (both dialects normalize to this split).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct UsageDelta {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

impl UsageDelta {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens + self.cache_read_tokens + self.cache_write_tokens
    }
}

/// Per-MTok USD prices, one rate per token category. Primary cost numbers
/// come from the facade tee (this table); the LiteLLM callback remains a
/// stub. OpenAI rates are best-effort estimates pinned here so the cost
/// budget is never blind for a known family; correct them as list prices
/// move.
#[derive(Debug, Clone, Copy)]
pub struct ModelPrice {
    pub input_per_mtok: f64,
    pub cached_input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub cache_write_per_mtok: f64,
}

pub fn price_for(model: &str) -> Option<ModelPrice> {
    let m = model.to_ascii_lowercase();
    // Anthropic: cache read = 0.1× input; 5-minute cache write = 1.25× input.
    let anthropic = |input: f64, output: f64| ModelPrice {
        input_per_mtok: input,
        cached_input_per_mtok: input * 0.1,
        output_per_mtok: output,
        cache_write_per_mtok: input * 1.25,
    };
    // OpenAI: cached input = 0.1× input; no cache-write charge.
    let openai = |input: f64, output: f64| ModelPrice {
        input_per_mtok: input,
        cached_input_per_mtok: input * 0.1,
        output_per_mtok: output,
        cache_write_per_mtok: 0.0,
    };
    // Rates are per-MTok USD, effective 2026-07 (Anthropic + OpenAI public
    // list prices; the facade tee is the primary meter — the LiteLLM
    // callback stays a stub). Estimates: correct as list prices move. The
    // gpt-5 catch-all deliberately charges the BIG-tier rate so any
    // unrecognized gpt-5 variant OVER-estimates — fail-safe for the cost
    // budget (an unknown model stops the run earlier, never later). A model
    // family we don't know at all returns None → the run leans on token /
    // wall-clock / tool-call budgets instead.
    let p = if m.contains("opus-4") {
        anthropic(5.0, 25.0)
    } else if m.contains("sonnet-5") || m.contains("sonnet-4") {
        anthropic(2.0, 10.0)
    } else if m.contains("haiku-4") {
        anthropic(1.0, 5.0)
    } else if m.starts_with("gpt-5") && m.contains("mini") {
        // gpt-5.4-mini — the codex default (cheap tier).
        openai(0.25, 2.0)
    } else if m.starts_with("gpt-5") {
        // gpt-5.4 / 5.5 / 5.6-{luna,sol,terra} + unknown gpt-5* → big-tier
        // (conservative upper bound).
        openai(1.25, 10.0)
    } else {
        return None;
    };
    Some(p)
}

pub fn estimate_cost_usd(model: &str, u: &UsageDelta) -> Option<f64> {
    let p = price_for(model)?;
    let mtok = 1_000_000.0;
    Some(
        u.input_tokens as f64 / mtok * p.input_per_mtok
            + u.output_tokens as f64 / mtok * p.output_per_mtok
            + u.cache_read_tokens as f64 / mtok * p.cached_input_per_mtok
            + u.cache_write_tokens as f64 / mtok * p.cache_write_per_mtok,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haiku_cost_math() {
        let u = UsageDelta {
            input_tokens: 1_000_000,
            output_tokens: 200_000,
            cache_read_tokens: 500_000,
            cache_write_tokens: 100_000,
        };
        let c = estimate_cost_usd("claude-haiku-4-5-20251001", &u).unwrap();
        // 1.0 + 0.2*5 + 0.5*0.1 + 0.1*1.25 = 1 + 1 + 0.05 + 0.125
        assert!((c - 2.175).abs() < 1e-9);
    }

    #[test]
    fn gpt_mini_cost_math_no_cache_write_charge() {
        let u = UsageDelta {
            input_tokens: 1_000_000,
            output_tokens: 500_000,
            cache_read_tokens: 2_000_000,
            cache_write_tokens: 1_000_000, // never charged on OpenAI
        };
        let c = estimate_cost_usd("gpt-5.4-mini", &u).unwrap();
        // 0.25 + 0.5*2.0 + 2.0*0.025 + 0
        assert!((c - 1.30).abs() < 1e-9);
    }

    #[test]
    fn gpt_big_tier_and_family_fallbacks() {
        assert!(price_for("gpt-5.4-mini").is_some());
        assert!(price_for("gpt-5.4").is_some());
        assert!(price_for("gpt-5.6-sol").is_some());
        let mini = price_for("gpt-5.4-mini").unwrap();
        let big = price_for("gpt-5.6-sol").unwrap();
        assert!(mini.input_per_mtok < big.input_per_mtok);
    }

    #[test]
    fn unknown_model_returns_none() {
        assert!(price_for("gpt-4o").is_none());
        assert!(price_for("mystery-model").is_none());
    }
}
