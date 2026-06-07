"""Parse a getpeercert()-style dict into something tidy.

The dicts we get from ssl.getpeercert() (and from the offline decode trick
ssl._ssl._test_decode_cert) have an awkward nested-tuple shape. Everything
here is pure so it is easy to test without touching the network.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _name_to_dict(name: tuple | None) -> dict[str, str]:
    # subject/issuer look like ((('commonName', 'x'),), (('organizationName', 'y'),))
    out: dict[str, str] = {}
    for rdn in name or ():
        for key, value in rdn:
            out.setdefault(key, value)
    return out


def _parse_cert_time(value: str) -> datetime:
    # openssl style, e.g. 'Jun  1 12:00:00 2027 GMT' (note the double space
    # before single-digit days). collapse whitespace so strptime is happy.
    text = " ".join(value.split())
    if text.endswith(" GMT"):
        text = text[:-4]
    return datetime.strptime(text, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)


def decode_cert_file(path: str) -> dict:
    """Decode a PEM cert on disk without a network connection.

    Uses the stdlib test hook, which returns the same dict shape as
    getpeercert(). Handy for `certwatch inspect` and for tests.
    """
    return ssl._ssl._test_decode_cert(path)


@dataclass
class CertInfo:
    host: str
    port: int
    subject: str | None
    issuer: str | None
    issuer_org: str | None
    not_before: datetime | None
    not_after: datetime | None
    sans: list[str] = field(default_factory=list)
    days_left: int | None = None

    @classmethod
    def from_cert_dict(
        cls,
        cert: dict,
        host: str,
        port: int = 443,
        now: datetime | None = None,
    ) -> CertInfo:
        now = now or datetime.now(timezone.utc)
        subject = _name_to_dict(cert.get("subject"))
        issuer = _name_to_dict(cert.get("issuer"))

        not_before = _parse_cert_time(cert["notBefore"]) if cert.get("notBefore") else None
        not_after = _parse_cert_time(cert["notAfter"]) if cert.get("notAfter") else None

        sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

        days_left = None
        if not_after is not None:
            days_left = (not_after - now).days

        return cls(
            host=host,
            port=port,
            subject=subject.get("commonName"),
            issuer=issuer.get("commonName"),
            issuer_org=issuer.get("organizationName"),
            not_before=not_before,
            not_after=not_after,
            sans=sans,
            days_left=days_left,
        )
