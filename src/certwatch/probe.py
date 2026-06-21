"""Live TLS probe. Connect, grab the peer cert, hand back a CertInfo.

Note on verification: we deliberately do NOT verify the chain. We are not
establishing a secure session, we just want to read the cert and check when it
expires. If we verified, an already-expired cert would raise before we could
report it, which is exactly the case we care about. Because getpeercert()
returns an empty dict when the peer isn't validated, we pull the DER form and
decode it with the same offline trick used by `inspect`.
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime

from certwatch.certinfo import CertInfo


@dataclass
class ProbeResult:
    host: str
    port: int
    cert: CertInfo | None = None
    error: str | None = None


def _decode_der(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    fh = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        fh.write(pem)
        fh.close()
        return ssl._ssl._test_decode_cert(fh.name)
    finally:
        os.unlink(fh.name)


def probe_host(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    now: datetime | None = None,
) -> ProbeResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # SNI matters, plenty of hosts serve different certs per name
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except TimeoutError:
        return ProbeResult(host, port, error="connection timed out")
    except ssl.SSLError as exc:
        return ProbeResult(host, port, error=f"tls handshake failed: {exc}")
    except OSError as exc:
        return ProbeResult(host, port, error=str(exc))

    if not der:
        return ProbeResult(host, port, error="no certificate presented")

    cert = _decode_der(der)
    info = CertInfo.from_cert_dict(cert, host, port, now=now)
    return ProbeResult(host, port, cert=info)
