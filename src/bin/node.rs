use anyhow::Result;
use clap::Parser;
use crbb::node::{run, Config};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "CRBB node")]
struct Args {
    /// Path to a JSON config file
    #[arg(short, long)]
    config: PathBuf,
        /// Override variant: "crbb" (default) or "crbb-h".
    #[arg(long)]
    variant: Option<String>,

    /// Byzantine mode for this process: honest, s1, s2, s3, s4, s6.
    #[arg(long)]
    byzantine: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let bytes = tokio::fs::read(&args.config).await?;
    let cfg: Config = serde_json::from_slice(&bytes)?;
    let mut cfg: Config = serde_json::from_slice(&bytes)?;
    if let Some(v) = args.variant {
        cfg.variant = v;
    }
    if let Some(b) = args.byzantine {
        cfg.byzantine.mode = match b.as_str() {
            "honest" | "" => crate::byzantine::ByzantineMode::Honest,
            "s1" => crate::byzantine::ByzantineMode::WithholdShares,
            "s2" => crate::byzantine::ByzantineMode::ForgeSupply,
            "s3" => crate::byzantine::ByzantineMode::EquivocateVK,
            "s4" => crate::byzantine::ByzantineMode::WithholdBeyondK,
            "s6" => crate::byzantine::ByzantineMode::FloodPending,
            _ => panic!("unknown byzantine mode: {}", b),
        };
    }
    run(cfg).await
}