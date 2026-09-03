//! Generate schema and migration ConfigMaps with the `pg-gen` library API.
//!
//! Writes throwaway SQL fixtures to a temp dir so the example is self-contained:
//!
//! ```sh
//! cargo run -p pg-gen --example configmap
//! ```

use std::{fs, path::PathBuf};

use eyre::Result;
use pg_gen::ConfigMapBuilder;

fn main() -> Result<()> {
    let root = fixtures()?;

    let schema = ConfigMapBuilder::new("example-schema")
        .namespace("example")
        .label("app.kubernetes.io/name", "example-schema")
        .label("app.kubernetes.io/component", "schema")
        .data_from_file("schema.sql", &root.join("schema.sql"))?
        .build();

    let migrations = ConfigMapBuilder::new("example-migrations")
        .label("app.kubernetes.io/name", "example-migrations")
        .label("app.kubernetes.io/component", "migration")
        .data_from_migration_dir(&root.join("migrations"))?
        .build();

    print!("{}---\n{}", schema.to_yaml()?, migrations.to_yaml()?);
    Ok(())
}

fn fixtures() -> Result<PathBuf> {
    let root = std::env::temp_dir().join("pg-gen-example");
    let migrations = root.join("migrations");
    fs::create_dir_all(&migrations)?;

    fs::write(
        root.join("schema.sql"),
        "CREATE TABLE users (id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE);\n",
    )?;
    fs::write(
        migrations.join("20240101000000_init.sql"),
        "CREATE TABLE users (id BIGSERIAL PRIMARY KEY);\n",
    )?;
    fs::write(
        migrations.join("20240102000000_email.sql"),
        "ALTER TABLE users ADD COLUMN email TEXT NOT NULL UNIQUE;\n",
    )?;

    Ok(root)
}
