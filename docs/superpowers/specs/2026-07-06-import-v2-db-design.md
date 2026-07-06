# Import from another v2 database

## Summary

Add an `import` CLI subcommand that reads all credentials from a source v2
database and inserts them into a target v2 database, skipping exact duplicates
(site + account + password match). The two databases may use different master
passwords.

## Motivation

Currently VanillaPM can only import credentials from:

- **v1 legacy databases** via the `migrate` command
- **CSV files** via the REPL `load` command

There is no way to merge the contents of two v2 databases, e.g., after using
separate databases on different machines or sharing a subset of credentials.

## CLI syntax

```
vanillapm target.data import source.data [--source-key-db source.key]
```

- `target.data` — positional `db` argument, the destination database
- `source.data` — the source database to read from
- `--source-key-db` — optional separate key database for the source
- The target's separate key database uses the existing `-k`/`--key-db` flag

## Flow

1. Prompt for the **source** database password interactively
2. Open the source v2 database with `SQLiteManager::new_with_passwd`
3. Read all items from the source via `get_all_items()`
4. Prompt for the **target** database password interactively
5. Open the target v2 database with `SQLiteManager::new_with_passwd`
6. Read all existing items from the target via `get_all_items()`
7. Build a dedup set from existing items: `(site, account, password)` tuples
8. Insert only source items not already in the dedup set
9. Report: `Imported X items, skipped Y duplicates.`
10. Call `finish()` on the target

## Deduplication

An item is considered a duplicate when **all three fields** are identical:
`(site, account, password)`. This is the safest check — it won't silently
skip a site that has a different password or account.

Using `Vec<Item>` for the dedup set is fine for realistic vault sizes
(thousands of entries). Memory overhead of full decryption is acceptable
given this is a one-shot import, not a hot path.

## Code changes

### `src/engine/sqlite.rs`

- Make `get_all_items()` public (currently `fn get_all_items` → `pub fn get_all_items`)

### `src/main.rs`

- Add `Import` variant to the `Command` enum in the `define_cmd!` macro
- Add `do_import()` function
- Wire `Import` into the early-return block alongside `Migrate`

No changes to `DataManager` trait, `framework.rs`, or any new engine code.

## Error handling

| Scenario | Behavior |
|---|---|
| Wrong source password | Prompt again (3 retries) |
| Wrong target password | Prompt again (3 retries) |
| Source is a legacy v1 DB | Error: use `migrate` instead |
| Source has zero items | "Nothing to import" message, clean exit |
| Target deleted mid-import | Standard SQLite error propagation |

## Non-goals (out of scope)

- Importing from v1 databases (use `migrate` instead)
- Non-interactive password flags for import (just prompt)
- Dry-run mode
- Conflict resolution strategies (only exact-match dedup)
