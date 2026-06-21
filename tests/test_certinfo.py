from datetime import UTC

from certwatch.certinfo import CertInfo, decode_cert_file


def test_from_cert_dict_basic(sample_cert, now):
    info = CertInfo.from_cert_dict(sample_cert(), "example.com", now=now)
    assert info.host == "example.com"
    assert info.port == 443
    assert info.subject == "example.com"
    assert info.issuer == "R3"
    assert info.issuer_org == "Let's Encrypt"
    assert info.sans == ["example.com", "www.example.com"]


def test_days_left_is_deterministic(sample_cert, now):
    # notAfter one year after the fixed now
    info = CertInfo.from_cert_dict(sample_cert(), "example.com", now=now)
    assert info.days_left == 365


def test_days_left_negative_when_expired(sample_cert, now):
    info = CertInfo.from_cert_dict(
        sample_cert(not_after="Jan  1 12:00:00 2026 GMT"), "example.com", now=now
    )
    assert info.days_left < 0


def test_notafter_parsed_utc(sample_cert, now):
    info = CertInfo.from_cert_dict(sample_cert(), "example.com", now=now)
    assert info.not_after.tzinfo == UTC
    assert info.not_after.year == 2027


def test_single_digit_day_double_space(sample_cert, now):
    # 'Jun  1 ...' has the awkward double space; must still parse
    info = CertInfo.from_cert_dict(
        sample_cert(not_after="Jun  9 12:00:00 2027 GMT"), "example.com", now=now
    )
    assert info.not_after.day == 9


def test_missing_dates(sample_cert, now):
    cert = sample_cert()
    del cert["notAfter"]
    del cert["notBefore"]
    info = CertInfo.from_cert_dict(cert, "example.com", now=now)
    assert info.not_after is None
    assert info.not_before is None
    assert info.days_left is None


def test_no_san(sample_cert, now):
    cert = sample_cert()
    del cert["subjectAltName"]
    info = CertInfo.from_cert_dict(cert, "example.com", now=now)
    assert info.sans == []


def test_decode_real_pem(cert_file):
    cert = decode_cert_file(cert_file)
    info = CertInfo.from_cert_dict(cert, "example.test", port=0)
    assert info.subject == "example.test"
    assert "example.test" in info.sans
