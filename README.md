# certwatch

TLS certificate expiry monitor for the terminal. Point it at a list of hosts,
get back a table sorted worst-first and an exit code you can wire into cron or a
CI job.

It does one thing: tells you when certs expire, before they do.

## Install

```sh
pip install certwatch
```

Or from a checkout:

```sh
pip install -e .
```

Python 3.11+. The only runtime dependency is `rich`.

## Usage

Check one or more hosts:

```sh
certwatch example.com github.com badssl.com:443
```

```
                          certificate expiry
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ host          ┃ status   ┃ days left ┃ expires             ┃ issuer        ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ old.example   │ critical │         4 │ 2026-06-05T12:00:00 │ Let's Encrypt │
│ example.com   │ warning  │        16 │ 2026-06-17T12:00:00 │ Let's Encrypt │
│ github.com    │ ok       │       213 │ 2027-01-01T00:00:00 │ Sectigo       │
└───────────────┴──────────┴───────────┴─────────────────────┴───────────────┘
```

Read hosts from a file (one per line, `#` comments allowed):

```sh
certwatch --targets hosts.txt
```

```
# hosts.txt
example.com
api.example.com:8443
internal.box    # non-standard port works too
```

Inspect a PEM file offline, no network:

```sh
certwatch inspect /etc/ssl/certs/mycert.pem
```

Machine-readable output for scripts:

```sh
certwatch --json example.com | jq '.[] | select(.status != "ok")'
```

## Thresholds and exit codes

`--warn` (default 21 days) and `--critical` (default 7 days) control the status
buckets. The process exit code is the worst status seen across all hosts, which
is what makes it useful in cron:

| status   | meaning                        | exit |
|----------|--------------------------------|------|
| ok       | more than `--warn` days left   | 0    |
| warning  | within `--warn` days           | 1    |
| critical | within `--critical` days       | 2    |
| expired  | already past `notAfter`        | 2    |
| error    | host unreachable / no cert     | 3    |

Example cron line that mails you only when something is actually wrong:

```sh
0 8 * * *  certwatch --targets /etc/certwatch/hosts.txt || echo "certs need attention" | mail -s certwatch you@example.com
```

## Notes on the probe

certwatch connects and reads the presented certificate but does **not** verify
the chain. That's deliberate: an already-expired cert would otherwise raise
during the handshake, and the expired case is exactly the one you want reported.
SNI is sent, so hosts serving different certs per name resolve correctly.

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT. See [LICENSE](LICENSE).
