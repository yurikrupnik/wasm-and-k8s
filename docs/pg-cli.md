# Command-Line Help for `pg-cli`

This document contains the help content for the `pg-cli` command-line program.

**Command Overview:**

* [`pg-cli`↴](#pg-cli)
* [`pg-cli configmap`↴](#pg-cli-configmap)
* [`pg-cli configmap schema`↴](#pg-cli-configmap-schema)
* [`pg-cli configmap migrations`↴](#pg-cli-configmap-migrations)

## `pg-cli`

Playground CLI — config & manifest generation

**Usage:** `pg-cli <COMMAND>`

###### **Subcommands:**

* `configmap` — Generate Kubernetes ConfigMaps from SQL files



## `pg-cli configmap`

Generate Kubernetes ConfigMaps from SQL files

**Usage:** `pg-cli configmap <COMMAND>`

###### **Subcommands:**

* `schema` — Generate schema ConfigMap from schema.sql
* `migrations` — Generate migrations ConfigMap from migration SQL files



## `pg-cli configmap schema`

Generate schema ConfigMap from schema.sql

**Usage:** `pg-cli configmap schema [OPTIONS]`

###### **Options:**

* `--schema <SCHEMA>` — Path to schema.sql

  Default value: `manifests/db/schema.sql`
* `--name <NAME>` — ConfigMap name

  Default value: `mydatabase-schema`
* `--namespace <NAMESPACE>` — ConfigMap namespace

  Default value: `dbs`
* `-o`, `--output <OUTPUT>` — Write output to file(s) instead of stdout



## `pg-cli configmap migrations`

Generate migrations ConfigMap from migration SQL files

**Usage:** `pg-cli configmap migrations [OPTIONS]`

###### **Options:**

* `--migrations-dir <MIGRATIONS_DIR>` — Path to migrations directory

  Default value: `manifests/db/migrations`
* `--name <NAME>` — ConfigMap name

  Default value: `mydatabase-migrations`
* `-o`, `--output <OUTPUT>` — Write output to file(s) instead of stdout



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
