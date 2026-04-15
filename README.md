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

## Security model

VanillaPM uses a layered encryption scheme. Understanding the threat model
helps you decide whether the defaults are sufficient for your use case.

### How data is protected (v2 format)

1. **Master password** → PBKDF2-HMAC-SHA256 (600 000 iterations, 32-byte random salt) → **AES-256 key**
2. AES-256-CBC encrypts the RSA private key and HMAC key at rest.
3. Each credential (site, account, password) is individually encrypted with **RSA-8192 OAEP** plus a 333-byte random salt.
4. Site names are indexed via **HMAC-SHA256** so exact-match queries work without decrypting every row.

### If your database files are leaked (without the master password)

An attacker who obtains the `.data` (and `.key`) files but **not** the master
password can only recover credentials by brute-forcing the password through
PBKDF2. The KDF salt and encrypted private key stored in the database give
them a clear verification oracle (valid PEM = correct guess).

Rough brute-force estimates (single RTX 4090-class GPU, ~3 000 guesses/sec):

| Password strength | Time to crack |
| --- | --- |
| Top-1M dictionary word | **~minutes** |
| 8-char random alphanumeric | **~1 400 years** |
| 16+ char random passphrase | **effectively infeasible** |

**Your security is exactly as strong as your master password.**

### Separate key database (`-k`) as defense-in-depth

When you use `-k mykeys.key`, all cryptographic keys (KDF salt, encrypted
private key, HMAC key, public key) are stored in a separate SQLite file. If
**only** the `.data` file leaks, the attacker has nothing but RSA-OAEP
ciphertext blobs — no material to brute-force against. Storing the two files
in different locations (e.g. different cloud providers) meaningfully reduces
risk.

### Recommendations

- Use a **strong, unique master password** (16+ characters or a multi-word passphrase).
- Prefer `--ask-password` or the `VANILLAPM_PASSWORD` env var over `-p` on the command line — CLI arguments are visible in `ps` output and shell history.
- Consider using the separate key database (`-k`) and storing the key file separately from the data file.

### TODO

- [ ] **Switch from PBKDF2 to Argon2id** — PBKDF2 is GPU-friendly, meaning attackers can parallelise brute-force attempts cheaply. Argon2id is memory-hard, making each guess ~10–100× more expensive on GPUs. This is the single most impactful improvement for the leaked-database threat model.

## License

This project does not currently specify a license.
