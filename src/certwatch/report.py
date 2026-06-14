"""Build report rows from probe results and render them as a table."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from certwatch.evaluate import Status, evaluate, exit_code_for
from certwatch.probe import ProbeResult

_STATUS_STYLE = {
    "ok": "green",
    "warning": "yellow",
    "critical": "red",
    "expired": "bold red",
    "error": "dim red",
}

# used to sort worst-first; mirrors evaluate.rank but keyed by string
_RANK = {"expired": 4, "error": 3, "critical": 2, "warning": 1, "ok": 0}


def to_entries(
    results: list[ProbeResult],
    warn: int = 21,
    critical: int = 7,
) -> list[dict]:
    entries: list[dict] = []
    for result in results:
        if result.error is not None:
            entries.append(
                {
                    "host": result.host,
                    "port": result.port,
                    "status": Status.ERROR.value,
                    "days_left": None,
                    "not_after": None,
                    "subject": None,
                    "issuer": None,
                    "sans": [],
                    "error": result.error,
                }
            )
            continue

        cert = result.cert
        status = evaluate(cert.days_left, warn, critical)
        entries.append(
            {
                "host": result.host,
                "port": result.port,
                "status": status.value,
                "days_left": cert.days_left,
                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                "subject": cert.subject,
                "issuer": cert.issuer_org or cert.issuer,
                "sans": cert.sans,
                "error": None,
            }
        )

    entries.sort(key=_sort_key)
    return entries


def _sort_key(entry: dict) -> tuple[int, int]:
    days = entry["days_left"]
    days = 10**9 if days is None else days
    return (-_RANK[entry["status"]], days)


def exit_code(entries: list[dict]) -> int:
    return exit_code_for([Status(entry["status"]) for entry in entries])


def render_table(entries: list[dict], console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="certificate expiry")
    table.add_column("host")
    table.add_column("status")
    table.add_column("days left", justify="right")
    table.add_column("expires")
    table.add_column("issuer")

    for entry in entries:
        style = _STATUS_STYLE.get(entry["status"], "")
        host = entry["host"]
        if entry["port"] not in (443, 0):
            host = f"{host}:{entry['port']}"
        days = "-" if entry["days_left"] is None else str(entry["days_left"])
        expires = entry["not_after"] or (entry["error"] or "")
        issuer = entry["issuer"] or ""
        table.add_row(
            host,
            f"[{style}]{entry['status']}[/{style}]",
            days,
            expires,
            issuer,
        )

    console.print(table)
