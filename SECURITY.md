# Security

certwatch makes outbound TLS connections and reads certificates. It doesn't
handle secrets and doesn't store anything, so the surface is small, but a couple
of notes.

If you find a security issue, please don't open a public issue. Email me at
75739931+OneNobleSoul@users.noreply.github.com with details and I'll get back to
you.

Worth knowing:

- The probe intentionally does not verify the certificate chain (see the README).
  It reads the presented cert to report expiry and nothing more - it never
  establishes a trusted session or sends data.
- `inspect` decodes a local PEM using the stdlib and touches no network.
- Only the latest release gets fixes.
