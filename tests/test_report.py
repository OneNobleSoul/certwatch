import json

from certwatch.certinfo import CertInfo
from certwatch.probe import ProbeResult
from certwatch.report import exit_code, render_json, render_table, to_entries


def _result(host, days_left, error=None, port=443):
    cert = None
    if error is None:
        cert = CertInfo(
            host=host,
            port=port,
            subject=host,
            issuer="R3",
            issuer_org="Let's Encrypt",
            not_before=None,
            not_after=None,
            sans=[host],
            days_left=days_left,
        )
    return ProbeResult(host, port, cert=cert, error=error)


def test_entries_status_mapping():
    entries = to_entries([_result("a.com", 60)])
    assert entries[0]["status"] == "ok"


def test_error_result_becomes_error_entry():
    entries = to_entries([_result("bad.com", None, error="connection timed out")])
    assert entries[0]["status"] == "error"
    assert entries[0]["error"] == "connection timed out"
    assert entries[0]["days_left"] is None


def test_worst_sorted_first():
    entries = to_entries(
        [
            _result("ok.com", 90),
            _result("expired.com", -3),
            _result("warn.com", 15),
            _result("crit.com", 3),
        ]
    )
    order = [e["host"] for e in entries]
    assert order[0] == "expired.com"
    assert order.index("crit.com") < order.index("warn.com") < order.index("ok.com")


def test_ties_sorted_by_days_left():
    entries = to_entries([_result("later.com", 20), _result("sooner.com", 10)])
    # both WARNING, fewer days first
    assert entries[0]["host"] == "sooner.com"


def test_exit_code_reflects_worst():
    entries = to_entries([_result("ok.com", 90), _result("crit.com", 2)])
    assert exit_code(entries) == 2


def test_render_json_roundtrip():
    entries = to_entries([_result("a.com", 60)])
    parsed = json.loads(render_json(entries))
    assert parsed[0]["host"] == "a.com"
    assert parsed[0]["status"] == "ok"


def test_render_table_smoke(capsys):
    entries = to_entries([_result("a.com", 60), _result("b.com", None, error="boom")])
    render_table(entries)
    out = capsys.readouterr().out
    assert "a.com" in out
    assert "b.com" in out
