from datetime import UTC, datetime
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"


@pytest.fixture
def now():
    # fixed reference so days_left is deterministic
    return datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def sample_cert():
    def make(not_after="Jun  1 12:00:00 2027 GMT", **overrides):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": (
                (("countryName", "US"),),
                (("organizationName", "Let's Encrypt"),),
                (("commonName", "R3"),),
            ),
            "notBefore": "Jun  1 12:00:00 2026 GMT",
            "notAfter": not_after,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        cert.update(overrides)
        return cert

    return make


@pytest.fixture
def cert_file():
    return str(DATA / "example-cert.pem")
