# Public review improvements

These changes are development work after the v1.1 preview. They are not a new published release or a claim of new Windows/PostgreSQL qualification.

## Analyst access

Loopback development still opens directly. Named credentials are mandatory when `QWR_ENVIRONMENT` is not `development` or `QWR_API_HOST` is not loopback, including the internal Docker bind.

1. Create a random credential of at least 32 characters in a password manager.
2. Run `python scripts/configure_analyst.py your-name` and paste that credential into its hidden prompts.
3. Put the printed `QWR_ANALYST_TOKEN_HASHES` assignment in `.env`. The helper outputs only its SHA-256 digest. For several analysts, combine distinct names and hashes into one JSON object.
4. Restart the API and sign in to the console using the original credential.

The browser retains the credential only in memory. Reload or sign out to clear it. API clients send `Authorization: Bearer <credential>`. Server-verified names replace caller-supplied `X-Actor-ID` values before analyst changes and approvals reach their handlers. To revoke a credential, remove its hash and restart; to rotate one, replace the hash and restart.

All named analysts currently share the existing analyst permissions. This is not OIDC, role-based authorization, expiring sessions, or an Internet deployment profile. Use TLS beyond local development. Do not expose a loopback demo through a proxy or tunnel: the application validates its configured bind, not the external network topology.

Enrollment and endpoint HMAC authentication retain their own credentials. An analyst credential cannot authorize an unsigned QuietWard event or endpoint action result. With analyst access enabled, development-only synthetic event ingestion also requires an analyst credential; existing unauthenticated demo senders work only in the default loopback demo.

## Incident navigation

The Incidents screen searches titles or exact incident IDs and filters by host ID, severity, and status. It shows a count and pages of 50 results; **Older incidents** follows a cursor and **Newest page** returns to the beginning. **Refresh from newest** fetches current results. Edits may change ordering between requests, so this is not a frozen export snapshot.

`GET /api/v1/incidents/page` returns `items`, `total`, and `next_cursor`, with a configurable limit of 1–100. The existing list endpoint remains available.

## Bridge activity and first use

The overview refreshes its QuietWard activity card every 30 seconds. It reports the latest server receipt time, source version and receipts in the last 24 hours. A receipt within one hour is **recent**; older receipts are **idle**. No data and API errors are separate states. Receipt activity cannot prove endpoint service health or reveal its pending queue; the card explicitly says queue depth is unavailable. An offline event delivered today counts as a receipt today even if observed earlier.

Empty screens point to the seeded quick demo and the pairing walkthrough. Demo observations are synthetic and do not prove that a QuietWard bridge is paired.

## Dependency qualification

Direct backend requirements and the Starlette/AnyIO pair are pinned to the versions tested together on Python 3.12. AnyIO 4.15 deprecated the alias still used by Starlette 1.6.0's TestClient; 4.14.2 restores the existing warnings-as-errors test gate without suppressing warnings. This is a tested compatibility baseline, not a full transitive lockfile. Update the pair together and rerun `python -m pytest -W error`.

The frontend lockfile upgrades sharp to 0.35.4 for [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c). The updated install passes npm audit with zero reported vulnerabilities.
