# VanillaPM

A minimal, encrypted password manager CLI built in Rust.

## Features

- **AES-256-CBC + RSA hybrid encryption** — passwords are encrypted with a per-item RSA layer on top of AES, with PBKDF2-derived keys (600k iterations)
- **HMAC integrity verification** — detects tampering of stored credentials
- **Interactive REPL** — add, query, and list credentials interactively
- **One-shot CLI commands** — query credentials directly from the command line
- **CSV import** — bulk-import credentials from CSV files
- **Separate key database** — optionally store encryption keys in a separate SQLite file
- **Legacy migration** — migrate v1 (RSA-PKCS#1 only) databases to the current v2 format

## Building

```sh
cargo build --release
```

Requires system libraries: `libssl-dev` and `libsqlite3-dev` (on Debian/Ubuntu).

## Usage

### Interactive REPL (default)

```sh
vanillapm mydb.data
```

REPL commands:

| Command                    | Description                        |
| -------------------------- | ---------------------------------- |
| `add <site>`               | Add a new credential               |
| `query <site>`             | Exact match query by site          |
| `query one <site>`         | Return a single matching item      |
| `query like <pattern>`     | Fuzzy match query by site          |
| `query account <account>`  | Exact match query by account       |
| `query account like <pat>` | Fuzzy match query by account       |
| `list sites`               | List all stored sites              |
| `load <file.csv>`          | Import credentials from a CSV file |
| `help`                     | Show available commands            |
| `quit` / `exit`            | Exit the REPL                      |

### One-shot CLI

```sh
vanillapm mydb.data query-one --ask-password github.com
vanillapm mydb.data query -p "mypassword" github.com
```

The master password can also be supplied via the `VANILLAPM_PASSWORD` environment variable.

### Separate key database

```sh
vanillapm mydb.data -k mykeys.key
```

### Migrate a legacy v1 database

```sh
vanillapm old.data migrate new.data
```

## License

This project does not currently specify a license.
