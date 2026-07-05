# Changelog

## 0.1.0
- first cut: live TLS probe (SNI, no chain verification so expired certs still
  read), cert info parsing from the getpeercert dict, status thresholds with
  worst-wins exit codes, rich table sorted worst-first, `--json` output, and an
  `inspect` mode for local PEM files
