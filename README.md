# Zero-Trust Network Access: Cloudflare Tunnels and MFA

A small educational Flask admin console demonstrating layered access controls:
- **Cloudflare Tunnel** exposes the local origin through an outbound tunnel, avoiding an inbound public port.
- **Cloudflare Access** should enforce identity-aware access policies and MFA before requests reach the app.
- **Application TOTP MFA** adds a second application-level verification step.
- Secure session-cookie settings, generic login errors, and a basic in-memory login throttle are included.

> **Important:** This is a teaching/demo project, not a production-ready authentication service. The in-memory limiter is per-process, the sample does not implement account recovery or audit-log retention, and the optional Access-header check is not a substitute for cryptographic JWT validation. Do not use it to protect real sensitive systems without a security review.

## Project files

- `app.py` — Flask admin console with password + TOTP verification.
- `requirements.txt` — Python package dependencies.
- `requirements.pdf` — printable dependency list.
- `project_report.pdf` — project report, including the supplied university logo.
- `.env.example` — environment-variable template; contains placeholders only.
- `cloudflared-config.example.yml` — sample Tunnel ingress configuration.
- `university_logo.png` — supplied logo used in the report.

## Requirements

- Python 3.10 or newer
- A Cloudflare account and a domain/hostname managed by Cloudflare
- `cloudflared` installed on the host
- An authenticator app compatible with TOTP (for example, any RFC 6238-compatible authenticator)
- HTTPS hostname protected by Cloudflare Access

## 1. Install and run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

python -m pip install -r requirements.txt
```

Set the environment variables. Use unique, strong values and generate a Base32 TOTP secret securely. Do not commit `.env` or real secrets.

**PowerShell example:**
```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "use-a-strong-unique-password"
$env:MFA_SECRET = "YOUR_BASE32_TOTP_SECRET"
python app.py
```

**macOS/Linux example:**
```bash
export FLASK_SECRET_KEY='replace-with-a-long-random-secret'
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='use-a-strong-unique-password'
export MFA_SECRET='YOUR_BASE32_TOTP_SECRET'
python app.py
```

Visit `http://127.0.0.1:5000`. The application listens on localhost only. A blank password or MFA secret causes the app to refuse successful authentication.

## 2. Configure Cloudflare Tunnel

1. Install and authenticate `cloudflared` on the host following Cloudflare's official documentation.
2. Create a named Tunnel and route a DNS hostname such as `admin.example.com` to it.
3. Adapt `cloudflared-config.example.yml` with the actual Tunnel UUID, credentials-file path, hostname, and local service.
4. Run the Tunnel using the config file. Keep the origin bound to `127.0.0.1`; do not create a public inbound firewall rule for port 5000.
5. Store the Tunnel credentials outside the Git repository and restrict file permissions.

Example (after creating and configuring the tunnel):
```bash
cloudflared tunnel --config /etc/cloudflared/config.yml run
```

## 3. Configure Cloudflare Access and MFA

In Cloudflare Zero Trust:
1. Create a self-hosted Access application for `admin.example.com`.
2. Create an allow policy restricted to named users or an approved identity-provider group. Avoid broad public allow rules.
3. Configure an MFA requirement in the identity provider / Access policy as appropriate for your organization.
4. Test allowed and denied identities in a private browser session.
5. Enable application-level header presence check only if the origin is exclusively reachable through the protected Tunnel/Access path:
   `REQUIRE_CLOUDFLARE_ACCESS_HEADER=1`
6. For stronger origin-side verification, validate the `Cf-Access-Jwt-Assertion` JWT signature, issuer, audience, and expiry against Cloudflare's published public keys. Do not trust a user-supplied identity header if direct origin access is possible.

Cloudflare dashboard labels may change; follow the current Cloudflare Zero Trust documentation.

## Security notes / production hardening

- Use a secret manager or protected environment configuration; rotate credentials and secrets.
- Use a production WSGI server such as Gunicorn behind the Tunnel. Example: `gunicorn --bind 127.0.0.1:5000 app:app`.
- Set `COOKIE_SECURE=1` when the app is served through HTTPS and proxy behavior has been reviewed.
- Replace the in-memory throttle with a shared store and central rate limiting.
- Add audit logging, monitoring, alerting, account lifecycle management, backup MFA/recovery procedures, CSRF protection, and automated security tests.
- Validate Cloudflare Access JWTs at the origin if relying on identity claims; header presence alone is not authentication.
- Keep dependencies patched and perform a security review before production deployment.

## Troubleshooting

- **503 / setup incomplete:** set `ADMIN_PASSWORD` and `MFA_SECRET`.
- **Authenticator code rejected:** check that the device clock is synchronized and that the secret is a valid Base32 TOTP secret.
- **Access denied before app loads:** review the Cloudflare Access application, policy, identity provider, and MFA requirements.
- **Tunnel cannot connect:** check hostname routing, credentials-file path, and that the local app is running on `127.0.0.1:5000`.

## License

For educational and academic demonstration use. Add a license before redistributing this project.
