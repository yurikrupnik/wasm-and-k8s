//! Example consumer of the `pg-cli` binary.
//!
//! Demonstrates the intended integration pattern for other repos: install `pg-cli` to PATH
//! (`just install-pg-cli`), then invoke it as a subprocess, capture the YAML it prints to
//! stdout, and either inspect it or write it to a manifests directory.
//!
//! ```sh
//! cargo run -p pg-cli-example
//! cargo run -p pg-cli-example -- --pg-cli dist/target/debug/pg-cli --out-dir /tmp/manifests
//! ```

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use clap::Parser;
use color_eyre::eyre::{Context, Result, bail};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");

#[derive(Parser)]
#[command(
    name = "pg-cli-example",
    about = "Generate ConfigMaps by shelling out to pg-cli"
)]
struct Cli {
    /// Path to the pg-cli executable (defaults to `pg-cli` on PATH)
    #[arg(long, env = "PG_CLI", default_value = "pg-cli")]
    pg_cli: PathBuf,

    /// Directory to write generated manifests into
    #[arg(long, default_value = "dist/pg-cli-example")]
    out_dir: PathBuf,

    /// Namespace for the schema ConfigMap
    #[arg(long, default_value = "example")]
    namespace: String,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    let fixtures = Path::new(FIXTURES);

    let schema_path = fixtures.join("schema.sql");
    let migrations_dir = fixtures.join("migrations");

    let schema = run_pg_cli(
        &cli.pg_cli,
        &[
            "configmap",
            "schema",
            "--schema",
            path_arg(&schema_path)?,
            "--name",
            "example-schema",
            "--namespace",
            &cli.namespace,
        ],
    )?;

    let migrations = run_pg_cli(
        &cli.pg_cli,
        &[
            "configmap",
            "migrations",
            "--migrations-dir",
            path_arg(&migrations_dir)?,
            "--name",
            "example-migrations",
        ],
    )?;

    std::fs::create_dir_all(&cli.out_dir)
        .wrap_err_with(|| format!("creating {}", cli.out_dir.display()))?;

    for (file, yaml) in [
        ("schema-configmap.yaml", &schema),
        ("migrations-configmap.yaml", &migrations),
    ] {
        let path = cli.out_dir.join(file);
        std::fs::write(&path, yaml).wrap_err_with(|| format!("writing {}", path.display()))?;
        let (name, keys) = summarize(yaml)?;
        println!(
            "{} -> ConfigMap/{name} ({} data key(s): {})",
            path.display(),
            keys.len(),
            keys.join(", ")
        );
    }

    Ok(())
}

/// Run `pg-cli` with `args` and return its stdout as a string.
fn run_pg_cli(pg_cli: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(pg_cli).args(args).output().wrap_err_with(|| {
        format!(
            "spawning {} (install with `just install-pg-cli` or pass --pg-cli)",
            pg_cli.display()
        )
    })?;

    if !output.status.success() {
        bail!(
            "pg-cli {} exited with {}:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout).wrap_err("pg-cli stdout was not valid UTF-8")
}

/// Extract `metadata.name` and the sorted `data` keys from a ConfigMap YAML document.
fn summarize(yaml: &str) -> Result<(String, Vec<String>)> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).wrap_err("parsing pg-cli output")?;

    let name = doc["metadata"]["name"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing metadata.name in pg-cli output"))?
        .to_owned();

    let keys = doc["data"]
        .as_mapping()
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok((name, keys))
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| eyre::eyre!("non-UTF-8 path: {}", path.display()))
}
