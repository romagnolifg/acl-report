# acl-report

Import a filesystem ACL scan export into a SQLite database, then browse it in a
small local web UI. Standard library only; Python 3 (Linux or Windows).

## Workflow

1. Import a scan directory into a database:

   ```
   python importer.py SOURCE_DIR --database report.db
   ```

2. Serve that database:

   ```
   python server.py --database report.db
   ```

3. Browse:

   ```
   http://127.0.0.1:8000
   ```

On Linux/macOS use python3 where python is not Python 3; on Windows use python.
The launchers below do step 2 and resolve their own directory, so they work
from any working directory:

```
./run.sh [DATABASE]   # Linux/macOS; default: report.db beside the launcher
run.bat [DATABASE]    # Windows;     default: report.db beside the launcher
```

## Source files required

SOURCE_DIR must contain all five scanner outputs. If any is missing the import
aborts before the database is touched:

```
summary.json   manifest.jsonl   paths.csv   aces.csv   errors.jsonl
```

## Import is a full atomic rebuild

Each import builds a brand-new database in a temporary file
(.acl-import-*.tmp beside the target), runs PRAGMA integrity_check, and only
then swaps it into place with os.replace(). The target path is therefore only
ever the previous database or the new complete one, never a partial or
half-written file. This is a full rebuild, not an incremental update: re-run
the importer to refresh the database.

## Safety

The server binds 127.0.0.1 by default and opens the database read-only, one
connection per request. Localhost-only means the sensitive ACL data never
leaves the machine.

Binding to any non-loopback address is refused unless you pass --allow-remote:

```
python server.py --database report.db --host 0.0.0.0 --allow-remote
```

--allow-remote exposes ACL data to everyone who can reach the port. Use it only
on a trusted or firewalled network.

## Limitation: direct ACL vs effective access

The importer stores the ACL entries the scanner reported at each path: the
direct entries, their inheritance markers (inherited_from, no_propagate,
is_explicit), and the node hierarchy. It does not compute effective access.
There is no group-membership expansion and no allow/deny precedence evaluation
down the tree.

A path with no explicit entry may still be reachable through inheritance. Read
the inherited entries and their lineage rather than treating "no explicit ACE"
as "no access".

