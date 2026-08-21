# QuietWard Response v1.2 security operations

This runbook covers the v1.2 candidate's security-maintenance tools. It is standalone and applies only to QuietWard Response.

## 1. Check the live control plane

Set a responder/viewer token in your shell or enter it interactively when prompted:

```text
QWR_ANALYST_TOKEN=... python scripts/diagnose_response_security.py
```

For a remote API, use HTTPS:

```text
QWR_ANALYST_TOKEN=... python scripts/diagnose_response_security.py \
  --api-url https://response.example.internal
```

The diagnostic is read-only. It checks:

- API health;
- exact seven-action v1.2 registry;
- approval requirement on every registered action;
- absence of generic command/shell actions;
- audit-chain validity;
- freshness of enabled-agent signed capability reports;
- optional retained audit checkpoint.

Use `--strict` when stale or never-reported enabled agents should make the check fail.

## 2. Keep agent capabilities fresh

The official poll path signs capability state before asking for pending work:

```text
python scripts/poll_response_agent.py --config /absolute/path/to/agent.json
```

A non-demo v1.2 action is rejected when the target agent:

- never reported capabilities;
- has a report older than 15 minutes;
- reports an implausible future timestamp;
- does not list that exact action as locally enabled.

Disabling an agent clears its capability trust state and any staged key rotation. Re-enable does not restore response authority automatically; the agent must sign a new capability report.

## 3. Rotate an agent credential

Normal rotation:

```text
python scripts/rotate_response_agent_key.py \
  --config /absolute/path/to/agent.json
```

The helper:

1. uses the current credential to prepare one short-lived replacement;
2. writes the new credential into a private `.next` sidecar;
3. proves possession of the pending key to activate it;
4. immediately revokes the old key for normal agent traffic;
5. signs a normal capability report with the promoted credential;
6. atomically replaces the original configuration file.

The new secret is never printed.

If local promotion was interrupted after the `.next` file was safely written:

```text
python scripts/rotate_response_agent_key.py \
  --config /absolute/path/to/agent.json \
  --recover-next
```

Do not create a second rotation while a live pending rotation exists. The server deliberately refuses it so the staged recovery credential cannot be overwritten.

## 4. Export a signed audit anchor

Use a viewer-or-higher analyst token:

```text
QWR_ANALYST_TOKEN=... python scripts/manage_audit_checkpoint.py export \
  --file /absolute/independent/path/response-audit-checkpoint.json
```

The export file is written atomically and privately. Store it outside the Response database. A read-only mount, separate secured host, or independently managed backup location is preferable.

Verify later with:

```text
QWR_ANALYST_TOKEN=... python scripts/manage_audit_checkpoint.py verify \
  --file /absolute/independent/path/response-audit-checkpoint.json
```

The checkpoint anchors the historical audit prefix. It can detect a later consistent re-hash/rewrite or truncation of records already covered by that checkpoint.

## 5. Enforce an audit anchor during startup

Set:

```text
QWR_AUDIT_CHECKPOINT_SECRET=<independent-32+-character-secret>
QWR_TRUSTED_AUDIT_CHECKPOINT_PATH=/absolute/path/response-audit-checkpoint.json
```

When configured, Response refuses startup if the retained checkpoint is missing, malformed, forged, or inconsistent with current history.

On POSIX, the configured checkpoint must also be a regular non-symlink file and must not be group/world writable. A 0444 or 0600 file on a controlled mount is appropriate.

## 6. Scan stored data for credential-like persistence

Run against the configured Response database:

```text
python scripts/audit_sensitive_persistence.py
```

Or specify a database explicitly:

```text
python scripts/audit_sensitive_persistence.py \
  --database-url sqlite:////absolute/path/quietward-response.db
```

The scanner checks durable event payloads/summaries, action result/evidence/error fields, approval rejection reasons, and audit details using the current redaction rules.

On failure it prints only:

`table:record_id:field`

It never prints the discovered credential-like value.

A clean scan does not mean the database is non-sensitive; it means the current obvious credential-redaction policy found no persisted value it would remove.

## 7. Protect local credential files

The Response-agent configuration and rotation `.next` sidecar contain credentials. Keep them out of source control and backups that are not intended to contain endpoint secrets.

The v1.2 automated gate includes a tracked-artifact audit that rejects common agent config filenames, staged `.next` agent credentials, non-example `.env` files, and private-key container extensions.

## 8. Integrity-failure behavior

When an incident contains explicit evidence/sensor/self-integrity compromise:

- low-risk diagnostics remain available;
- medium/high-impact host mutation is blocked by deterministic policy.

Do not bypass this by manually reconstructing an action through the database or another client. Restore sensor/evidence trust or investigate from an independent trusted source first.

## 9. Current credential-storage limitation

The v1.2 server still uses symmetric HMAC verification for active agents. Although normal APIs/logs do not expose that material and retired HMAC keys are not stored, a database disclosure that includes the active usable verification key remains security-significant.

The migration contract for v1.3 is documented in `docs/V13_AGENT_KEY_PROTECTION_DESIGN.md`. The preferred direction is endpoint-held asymmetric private signing keys so a database-only compromise is insufficient to forge agent traffic.

Do not replace this with home-grown encryption or obfuscation.

## 10. Release qualification

Before tagging v1.2:

```text
python scripts/finalize_v12_alpha.py
```

Then complete every item in `docs/V12_ALPHA_ACCEPTANCE.md` on the exact same candidate SHA.

A failed automated gate, sensitive-artifact audit, migration check, live disposable containment test, or browser smoke blocks release.
