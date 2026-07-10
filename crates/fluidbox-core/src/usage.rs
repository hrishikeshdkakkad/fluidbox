use serde::{Deserialize, Serialize};

/// Token usage for one model response (Anthropic shape, cache-aware).
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

/// Per-MTok USD prices. Primary cost numbers come from the LiteLLM gateway
/// callback; this table only backs the direct-Anthropic fallback path and
/// sanity checks. Cache read = 0.1× input; 5-minute cache write = 1.25× input.
#[derive(Debug, Clone, Copy)]
pub struct ModelPrice {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
}

pub fn price_for(model: &str) -> Option<ModelPrice> {
    let m = model.to_ascii_lowercase();
    let p = if m.contains("opus-4") {
        ModelPrice {
            input_per_mtok: 5.0,
            output_per_mtok: 25.0,
        }
    } else if m.contains("sonnet-5") || m.contains("sonnet-4") {
        ModelPrice {
            input_per_mtok: 2.0,
            output_per_mtok: 10.0,
        }
    } else if m.contains("haiku-4") {
        ModelPrice {
            input_per_mtok: 1.0,
            output_per_mtok: 5.0,
        }
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
            + u.cache_read_tokens as f64 / mtok * (p.input_per_mtok * 0.1)
            + u.cache_write_tokens as f64 / mtok * (p.input_per_mtok * 1.25),
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
    fn unknown_model_returns_none() {
        assert!(price_for("gpt-5").is_none());
    }
}
