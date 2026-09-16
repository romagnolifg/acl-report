# asustor_acl_inventory.py

Read-only recursive inventory of Windows ACLs on an ASUSTOR NAS running ADM.
It walks the virtual filesystem through ADM's File Explorer API and exports the
ACL of every path it finds as JSONL and CSV.

The script only ever calls these two API actions:

| Endpoint | Action | Purpose |
|---|---|---|
| `fileExplorer.cgi` | `act=file_list` | list directory contents |
| `acl.cgi` | `act=get&type=as_adv` | read ACLs |

There is no `set`, `reset`, `chown`, or recursive permission-change code in
the program. Nothing on the NAS is modified.

## Requirements

- Python 3.7+ (standard library only, no dependencies)
- Network access to ADM on the NAS
- An ADM account, or an existing session ID

## Quick start

Scan every shared folder the account can see:

```bash
python3 asustor_acl_inventory.py \
  --nas 'https://10.0.0.10:8001' \
  --insecure \
  --account 'admin' \
  --output './acl-all-shares'
```

`--insecure` skips TLS verification, which is normal for a self-signed ADM
certificate. If the NAS has a valid certificate or you have its CA, use
`--ca-cert ca.pem` instead. The two options are mutually exclusive.

## Recommended settings

Only `--retries` and
`--report-every` differ from the defaults.

```bash
python3 asustor_acl_inventory.py \
  --nas 'https://10.0.0.10:8001' \
  --insecure \
  --account 'admin' \
  --acl-workers 16 \
  --list-workers 4 \
  --timeout 60 \
  --hard-timeout 90 \
  --retries 1 \
  --report-every 100 \
  --output './acl-all-shares'
```

## How it works

The scan runs in two phases, and both are resumable:

1. **Discovery.** Concurrent directory listings build the path tree, honouring
   `--max-depth`. The result is cached in `manifest.jsonl`, so later runs
   skip the walk.
2. **ACL reads.** ACLs are fetched concurrently for every discovered path.
   Successful paths are appended to `inventory.jsonl` as they complete.

ACL responses are normalized: each ACE is written with its raw numeric
`perm` value preserved alongside the decoded rights (the 13 individual ASUSTOR
rights plus the `8192` Full Control marker), and with readable names for entry
type, authentication type, and inheritance flags.

By default only directories are scanned. Add `--include-files` to fetch file
ACLs too, which multiplies the request count.

## Authentication

Pick one of three modes.

**Managed login (recommended).** Pass `--account`; the script logs in, prompts
for the password without echo, and renews the SID automatically when ADM
returns error `5000`. The password stays in process memory and is never written
to output, the manifest, or shell history. One worker re-logs in while the rest
wait, then all retry with the new SID. If login fails, the scan stops safely
and stays resumable.

**Fixed SID.** Omit `--account` and paste a SID at the prompt, or set
`ASUSTOR_ADM_SID`. Fixed sessions cannot renew themselves, so the scan dies on
expiry.

**Password file (for unattended runs).** Keeps the password out of the prompt
and out of the environment:

```bash
install -m 600 /dev/null /protected/adm-password
read -rsp 'ADM password: ' PW; echo
printf '%s' "$PW" > /protected/adm-password
unset PW

python3 asustor_acl_inventory.py \
  --nas 'https://10.0.0.10:8001' --insecure \
  --account 'admin' --password-file /protected/adm-password \
  --output './acl-all-shares'
```

The file must not be readable by group or others (`chmod 600`), and the script
refuses to run otherwise. `ASUSTOR_ADM_ACCOUNT`, `ASUSTOR_ADM_PASSWORD`, and
`ASUSTOR_ADM_PASSWORD_FILE` work too, but environment variables are visible to
other privileged processes. The password is never accepted as a command-line
argument. OTP challenges are not implemented.

## Common invocations

One share, two levels deep, for a quick test:

```bash
python3 asustor_acl_inventory.py \
  --nas 'https://10.0.0.10:8001' --insecure --account 'admin' \
  --root '/volume1/projects' --max-depth 2 \
  --acl-workers 16 --output './acl-test'
```

Multiple roots, repeated flag:

```bash
  --root '/volume1/projects' --root '/volume2/backups'
```

Full subtree of one share, files included:

```bash
python3 asustor_acl_inventory.py \
  --nas 'https://10.0.0.10:8001' --insecure --account 'admin' \
  --root '/volume1/public' --include-files \
  --acl-workers 16 --output './acl-public-full'
```

## Resuming and re-scanning

Rerun the same command with the same `--output` directory and the scan picks up
where it stopped: paths already present in `inventory.jsonl` are skipped and
the cached manifest avoids walking the tree again. Failures are retried and
recorded in `errors.jsonl`. An interrupted scan (Ctrl-C) exits with status 130
and loses nothing.

Use `--refresh-manifest` after folders were added, removed, or renamed. A
change to the NAS URL, roots, depth, or `--include-files` invalidates the
manifest automatically. If discovery itself had errors, the manifest is not
cached so the next run retries it.

## Output files

All files are written to `--output` (default: a timestamped directory such as
`asustor-acl-inventory-20260916-120000`).

| File | Contents |
|---|---|
| `inventory.jsonl` | raw ACL response plus path metadata, one record per path; also errors |
| `manifest.jsonl` | cached recursive path inventory |
| `manifest-meta.json` | manifest scope, config, and completion state |
| `paths.csv` | one summary row per path (ACL enabled, ACE count, success) |
| `aces.csv` | one normalized row per ACE, with decoded rights |
| `errors.jsonl` | listing and ACL failures |
| `summary.json` | final statistics, timings, and effective settings |

The same summary is printed to stdout on completion, with progress and status
messages going to stderr.

Exit codes: `0` clean, `2` completed with errors, `3` stopped by
authentication, `130` interrupted.

## Options

```text
usage: asustor_acl_inventory.py [-h] --nas NAS [--root ROOT]
                                [--api-prefix API_PREFIX] [--account ACCOUNT]
                                [--password-file PASSWORD_FILE]
                                [--login-path LOGIN_PATH] [--insecure |
                                --ca-cert CA_CERT] [--output OUTPUT]
                                [--include-files] [--page-size PAGE_SIZE]
                                [--max-depth MAX_DEPTH]
                                [--acl-workers ACL_WORKERS]
                                [--list-workers LIST_WORKERS]
                                [--refresh-manifest]
                                [--report-every REPORT_EVERY]
                                [--timeout TIMEOUT]
                                [--hard-timeout HARD_TIMEOUT]
                                [--no-request-isolation] [--retries RETRIES]
                                [--delay DELAY]

Recursively inventory ASUSTOR Windows ACLs using read-only ADM APIs.

options:
  -h, --help            show this help message and exit
  --nas NAS             NAS base URL, e.g. https://nas:8001
  --root ROOT           ADM virtual root. Repeatable. Default: share (all
                        visible shares)
  --api-prefix API_PREFIX
                        ADM File Explorer API prefix
  --account ACCOUNT     ADM account for automatic login/renewal; password is
                        never accepted on CLI
  --password-file PASSWORD_FILE
                        Read ADM password from a mode-0600 file instead of
                        prompting
  --login-path LOGIN_PATH
                        ADM login API path
  --insecure            Disable TLS certificate verification (LAN interception
                        risk)
  --ca-cert CA_CERT     CA certificate file used to verify the NAS
  --output OUTPUT       Output directory; existing successful paths are
                        resumed
  --include-files       Also retrieve file ACLs; default is directories only
  --page-size PAGE_SIZE
                        Directory listing page size. Default: 500
  --max-depth MAX_DEPTH
                        Stop descending beyond this depth (0 scans only the
                        roots)
  --acl-workers ACL_WORKERS
                        Concurrent ACL reads. Default: 8; this NAS was stable
                        at 16
  --list-workers LIST_WORKERS
                        Concurrent directory listings. Default: 4
  --refresh-manifest    Rediscover the directory tree instead of reusing its
                        cached manifest
  --report-every REPORT_EVERY
                        Print ACL progress every N completed paths
  --timeout TIMEOUT     Per-request network timeout in seconds. Default: 60
  --hard-timeout HARD_TIMEOUT
                        Absolute per-attempt deadline enforced by an isolated
                        process
  --no-request-isolation
                        Disable the hard-kill subprocess failsafe (debugging
                        only)
  --retries RETRIES     Retry attempts per request after the first failure.
                        Default: 2
  --delay DELAY         Delay before each request in seconds
```

## Performance

`acl.cgi` is the bottleneck; single calls take roughly 3.5 s regardless of
path size. Measured throughput on one NAS:

| ACL workers | Throughput |
|---:|---:|
| 1 | 0.28 paths/s |
| 8 | 0.48 paths/s |
| 12 | 0.60 paths/s |
| 16 | 0.95 paths/s |

`8` is the conservative default. `16` ran without errors during testing and is
the fast setting, but watch NAS CPU and load on the first long run. Higher
values were not tested. Each request runs in a short-lived subprocess, so a
stuck request is hard-killed at `--hard-timeout` instead of hanging the scan.
