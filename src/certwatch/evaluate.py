"""Turn a days-left number into a status, and statuses into an exit code.

Pure functions, no I/O. This is the bit cron actually cares about.
"""

from __future__ import annotations

from enum import Enum


class Status(Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"
    ERROR = "error"


# exit code per status. worst one wins for the whole run.
_EXIT = {
    Status.OK: 0,
    Status.WARNING: 1,
    Status.CRITICAL: 2,
    Status.EXPIRED: 2,
    Status.ERROR: 3,
}

# how bad a status is for sorting the table (worst first). not the same as the
# exit code: an unreachable host is annoying but an expired cert is worse.
_RANK = {
    Status.EXPIRED: 4,
    Status.ERROR: 3,
    Status.CRITICAL: 2,
    Status.WARNING: 1,
    Status.OK: 0,
}


def evaluate(days_left: int | None, warn: int = 21, critical: int = 7) -> Status:
    if days_left is None:
        return Status.ERROR
    if days_left < 0:
        return Status.EXPIRED
    if days_left <= critical:
        return Status.CRITICAL
    if days_left <= warn:
        return Status.WARNING
    return Status.OK


def rank(status: Status) -> int:
    return _RANK[status]


def exit_code_for(statuses: list[Status]) -> int:
    return max((_EXIT[s] for s in statuses), default=0)
