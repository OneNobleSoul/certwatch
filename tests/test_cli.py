import json

import pytest

from certwatch.certinfo import CertInfo
from certwatch.cli import collect_targets, main, parse_target
from certwatch.probe import ProbeResult


def test_parse_target_default_port():
    assert parse_target("example.com") == ("example.com", 443)


def test_parse_target_explicit_port():
    assert parse_target("example.com:8443") == ("example.com", 8443)


def test_parse_target_bare_ipv6():
    assert parse_target("::1") == ("::1", 443)
    assert parse_target("2001:db8::1") == ("2001:db8::1", 443)


def test_parse_target_bracketed_ipv6():
    assert parse_target("[::1]") == ("::1", 443)


def test_parse_target_bracketed_ipv6_with_port():
    assert parse_target("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_parse_target_bad_port_raises_value_error():
    with pytest.raises(ValueError, match="not a valid port"):
        parse_target("example.com:notaport")


def test_parse_target_bad_bracketed_port_raises_value_error():
    with pytest.raises(ValueError, match="not a valid port"):
        parse_target("[::1]:notaport")


def test_parse_target_missing_closing_bracket_raises_value_error():
    with pytest.raises(ValueError, match="missing closing"):
        parse_target("[::1")


def test_parse_target_empty_brackets_raise_value_error():
    with pytest.raises(ValueError, match="empty host"):
        parse_target("[]")


def test_parse_target_trailing_text_after_bracket_raises_value_error():
    # a missing ':' before the port (e.g. "[::1]8443") must not be silently
    # swallowed into the default port - that would probe the wrong port.
    with pytest.raises(ValueError, match="unexpected text"):
        parse_target("[::1]8443")


def test_collect_targets_from_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("a.com\nb.com:8443\n# a comment\n\nc.com  # inline\n")
    targets = collect_targets(["cli.com"], str(f))
    assert ("cli.com", 443) in targets
    assert ("a.com", 443) in targets
    assert ("b.com", 8443) in targets
    assert ("c.com", 443) in targets
    assert len(targets) == 4


def _fake_probe(days_left):
    def probe(host, port=443, timeout=10.0, now=None):
        info = CertInfo(
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
        return ProbeResult(host, port, cert=info)

    return probe


def test_main_exit_code_ok(capsys):
    code = main(["good.com"], probe_fn=_fake_probe(90))
    assert code == 0


def test_main_exit_code_critical():
    code = main(["bad.com"], probe_fn=_fake_probe(2))
    assert code == 2


def test_main_json_output(capsys):
    main(["good.com", "--json"], probe_fn=_fake_probe(90))
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed[0]["host"] == "good.com"


def test_main_no_targets_errors():
    with pytest.raises(SystemExit):
        main([], probe_fn=_fake_probe(90))


def test_main_missing_targets_file_errors(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    with pytest.raises(SystemExit):
        main(["--targets", str(missing)], probe_fn=_fake_probe(90))
    assert "targets file" in capsys.readouterr().err


def test_main_malformed_port_errors_cleanly(capsys):
    with pytest.raises(SystemExit):
        main(["example.com:notaport"], probe_fn=_fake_probe(90))
    assert "not a valid port" in capsys.readouterr().err


def test_version(capsys):
    assert main(["--version"]) == 0
    assert "certwatch" in capsys.readouterr().out


def test_inspect_mode(cert_file, capsys):
    code = main(["inspect", cert_file, "--json"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed[0]["subject"] == "example.test"
    assert "example.test" in parsed[0]["sans"]
    assert code in (0, 1, 2)  # depends on the fixture cert's remaining lifetime
