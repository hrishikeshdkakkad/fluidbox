//! Exact `tracing_subscriber::EnvFilter` syntax check used by `just doctor`.

use tracing_subscriber::EnvFilter;

fn main() {
    let Some(filter) = std::env::args().nth(1) else {
        eprintln!("usage: validate_filter <directives>");
        std::process::exit(2);
    };
    if let Err(error) = EnvFilter::try_new(&filter) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
