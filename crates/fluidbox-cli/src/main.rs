//! `fluidbox` — the CLI client for the control plane.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "fluidbox",
    about = "Run governed AI coding agents in disposable sandboxes"
)]
struct Cli {
    /// Control plane URL (env: FLUIDBOX_API_URL)
    #[arg(
        long,
        env = "FLUIDBOX_API_URL",
        default_value = "http://127.0.0.1:8787"
    )]
    url: String,
    /// Admin token (env: FLUIDBOX_ADMIN_TOKEN)
    #[arg(long, env = "FLUIDBOX_ADMIN_TOKEN")]
    token: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a run of an agent and follow its timeline.
    Run {
        #[arg(long, default_value = "claude-fixer")]
        agent: String,
        #[arg(long)]
        task: String,
        /// Local repo path to work in (copied; original untouched).
        #[arg(long)]
        repo: Option<String>,
        /// Run without a human in the loop.
        #[arg(long)]
        autonomous: bool,
        /// Don't follow the timeline after starting.
        #[arg(long)]
        detach: bool,
    },
    /// List recent sessions.
    Sessions,
    /// Show one session (status, usage).
    Get { id: String },
    /// Follow a session's live event timeline.
    Watch { id: String },
    /// List pending approvals.
    Approvals,
    /// Approve a pending approval.
    Approve {
        id: String,
        /// Approve for the whole session (this tool/pattern).
        #[arg(long)]
        session: bool,
    },
    /// Deny a pending approval.
    Deny { id: String },
    /// List agents.
    Agents,
}

struct Client {
    http: reqwest::Client,
    url: String,
    token: String,
}

impl Client {
    fn new(url: String, token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
            token,
        }
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let res = self
            .http
            .get(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.json(res).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let res = self
            .http
            .post(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;
        self.json(res).await
    }

    async fn json(&self, res: reqwest::Response) -> Result<Value> {
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(anyhow!("HTTP {}: {}", status, text));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    if cli.token.is_empty() {
        return Err(anyhow!(
            "admin token required (--token or FLUIDBOX_ADMIN_TOKEN)"
        ));
    }
    let client = Client::new(cli.url, cli.token);

    match cli.cmd {
        Cmd::Run {
            agent,
            task,
            repo,
            autonomous,
            detach,
        } => {
            let repo_json = match repo {
                Some(p) => {
                    let abs = std::fs::canonicalize(&p)
                        .with_context(|| format!("repo path {p} not found"))?;
                    json!({ "kind": "local_path", "path": abs.to_string_lossy() })
                }
                None => json!({ "kind": "none" }),
            };
            let res = client
                .post(
                    "/v1/sessions",
                    json!({ "agent": agent, "task": task, "repo": repo_json, "autonomous": autonomous }),
                )
                .await?;
            let id = res["session"]["id"]
                .as_str()
                .ok_or_else(|| anyhow!("no session id"))?
                .to_string();
            println!(
                "▶ session {id}  (agent={agent}, autonomy={})",
                if autonomous {
                    "autonomous"
                } else {
                    "supervised"
                }
            );
            if detach {
                return Ok(());
            }
            watch(&client, &id).await?;
        }
        Cmd::Sessions => {
            let res = client.get("/v1/sessions?limit=20").await?;
            for s in res["sessions"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{}  {:<18}  {}",
                    &s["id"].as_str().unwrap_or("")[..8],
                    s["status"].as_str().unwrap_or(""),
                    s["task"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Get { id } => {
            let res = client.get(&format!("/v1/sessions/{id}")).await?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Cmd::Watch { id } => watch(&client, &id).await?,
        Cmd::Approvals => {
            let res = client.get("/v1/approvals").await?;
            let list = res["approvals"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("(no pending approvals)");
            }
            for a in list {
                println!(
                    "{}  session={}  {}  “{}”",
                    &a["id"].as_str().unwrap_or("")[..8],
                    &a["session_id"].as_str().unwrap_or("")[..8],
                    a["tool"].as_str().unwrap_or(""),
                    a["summary"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Approve { id, session } => {
            let decision = if session {
                "approved_session"
            } else {
                "approved_once"
            };
            let res = client
                .post(
                    &format!("/v1/approvals/{id}/decision"),
                    json!({ "decision": decision, "decided_by": "cli" }),
                )
                .await?;
            println!(
                "✓ {}",
                res["approval"]["status"].as_str().unwrap_or("decided")
            );
        }
        Cmd::Deny { id } => {
            client
                .post(
                    &format!("/v1/approvals/{id}/decision"),
                    json!({ "decision": "denied", "decided_by": "cli" }),
                )
                .await?;
            println!("✗ denied");
        }
        Cmd::Agents => {
            let res = client.get("/v1/agents").await?;
            for a in res["agents"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{}  {}",
                    a["name"].as_str().unwrap_or(""),
                    a["description"].as_str().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

/// Follow a session's SSE timeline until it reaches a terminal state.
async fn watch(client: &Client, id: &str) -> Result<()> {
    let url = format!("{}/v1/sessions/{}/events/stream", client.url, id);
    let res = client
        .http
        .get(&url)
        .bearer_auth(&client.token)
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(anyhow!("watch failed: HTTP {}", res.status()));
    }
    let mut stream = res.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buf.find("\n\n") {
            let raw = buf[..pos].to_string();
            buf.drain(..pos + 2);
            for line in raw.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    if let Ok(ev) = serde_json::from_str::<Value>(data.trim()) {
                        if print_event(&ev) {
                            return Ok(()); // terminal
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Returns true when the session has reached a terminal state.
fn print_event(ev: &Value) -> bool {
    let ty = ev["type"].as_str().unwrap_or("");
    let p = &ev["payload"]["data"];
    match ty {
        "session.status_changed" => {
            let to = p["to"].as_str().unwrap_or("");
            println!("  ● {to}");
            matches!(to, "completed" | "failed" | "cancelled" | "budget_exceeded")
        }
        "workspace.initialized" => {
            println!(
                "  ⬡ workspace ready (files={})",
                p["files"].as_u64().unwrap_or(0)
            );
            false
        }
        "agent.message" => {
            let role = p["role"].as_str().unwrap_or("");
            let text = p["text"].as_str().unwrap_or("");
            if !text.is_empty() {
                println!("  {role}: {}", truncate(text, 400));
            }
            false
        }
        "tool.requested" => {
            println!(
                "  🔧 {} — {}",
                p["tool"].as_str().unwrap_or(""),
                p["summary"].as_str().unwrap_or("")
            );
            false
        }
        "tool.decision" => {
            let v = p["verdict"].as_str().unwrap_or("");
            let sym = if v == "allow" { "✓" } else { "✗" };
            println!("     {sym} {} ({})", v, p["source"].as_str().unwrap_or(""));
            false
        }
        "approval.requested" => {
            println!(
                "  ⏸ APPROVAL NEEDED: {} — {}",
                p["tool"].as_str().unwrap_or(""),
                p["summary"].as_str().unwrap_or("")
            );
            println!(
                "     approve with: fluidbox approve {}",
                p["approval_id"].as_str().unwrap_or("")
            );
            false
        }
        "approval.decided" => {
            println!(
                "  ▶ approval {} by {}",
                p["decision"].as_str().unwrap_or(""),
                p["decided_by"].as_str().unwrap_or("")
            );
            false
        }
        "model.response" => {
            println!(
                "     ~ model {} (in={} out={} ${:.4})",
                p["model"].as_str().unwrap_or(""),
                p["input_tokens"].as_u64().unwrap_or(0),
                p["output_tokens"].as_u64().unwrap_or(0),
                p["cost_usd"].as_f64().unwrap_or(0.0)
            );
            false
        }
        "budget.exceeded" => {
            println!(
                "  ⚠ budget exceeded: {} (limit {})",
                p["budget"].as_str().unwrap_or(""),
                p["limit"].as_str().unwrap_or("")
            );
            false
        }
        "run.result" => {
            println!("  ✔ {}", p["outcome"].as_str().unwrap_or(""));
            false
        }
        "run.error" => {
            println!("  ✖ error: {}", p["message"].as_str().unwrap_or(""));
            false
        }
        _ => false,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
