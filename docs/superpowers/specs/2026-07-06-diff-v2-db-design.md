# Diff two v2 databases

## Summary

Add a `diff` CLI subcommand that compares two v2 databases and reports items
present in only one side, using (site, account, password) as the equality key.

## Motivation

After using `import` to merge databases, or when maintaining multiple vaults,
users need to see what differs between two databases — which credentials are
in one but not the other.

## CLI syntax

```
vanillapm db_a.data diff db_b.data [--other-key-db other.key]
```

- `db_a.data` — positional `db` argument, the first database
- `db_b.data` — argument of the `diff` subcommand, the second database
- `--other-key-db` — optional separate key database for `db_b`
- `db_a`'s separate key database uses the existing `-k`/`--key-db` flag

## Flow

1. Prompt for `db_a` password interactively
2. Open `db_a` with `SQLiteManager::new_with_passwd`, read all items
3. Prompt for `db_b` password interactively
4. Open `db_b` with `SQLiteManager::new_with_passwd`, read all items
5. Build `HashSet<(String, String, String)>` for each side
6. Print items only in A, then items only in B
7. Print summary: counts for only-in-A, only-in-B, in-common

## Output format

Tab-separated fields, grouped by side:

```
=== VanillaPM Diff ===
A: db_a.data
B: db_b.data

--- Only in A (N items) ---
site	account	password

--- Only in B (M items) ---
site	account	password

=== Summary: N only in A, M only in B, K in common ===
```

If one section is empty, skip printing it.

## Match key

`(site, account, password)` — all three fields must match exactly.
This is the same key used by the `import` dedup logic.

## Code changes

### `src/main.rs`

- Add `Diff` variant to the `Command` enum in `define_cmd!`
- Add `do_diff()` function
- Wire `Diff` into the early-return block in `main()` alongside `Migrate` and `Import`

No changes to any other file — `get_all_items()` is already public.

## Error handling

| Scenario | Behavior |
|---|---|
| Wrong password (either side) | Prompt again (3 retries) |
| Either DB is legacy v1 | Error: use `migrate` instead |
| One side is empty | Print items from the other side as the diff |

## Non-goals

- Field-level comparison (e.g., same site but different password)
- Diff of v1 databases
- Non-interactive password flags
