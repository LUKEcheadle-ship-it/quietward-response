# Threat model

## Assets and trust boundaries

Protected assets are incident evidence, host inventory, analyst decisions, recommendations, and the audit trail. Endpoint sensors, networks, browsers, and supplied event content are untrusted. The API and database form the initial trusted control plane; future endpoint action credentials must be isolated from ingestion credentials.

## Threats and initial controls

| Threat | Phase 1 controls | Required production follow-up |
|---|---|---|
| Forged events | Strict schema, bounded fields, source recorded | Source authentication, per-source host authorization, signing |
| Compromised endpoint agent | Treat event content as data; no command execution | Agent identity, revocation, anomaly detection, corroboration |
| Replay attacks | Globally unique event ID and duplicate rejection | Signed timestamp/nonce, bounded acceptance window, replay cache |
| Malicious response requests | No remediation execution or shell API exists | Separate action API, policy engine, approvals, allow-listed actions |
| API compromise | Environment-only secrets, safe CORS default, parameterized ORM queries | Authentication, RBAC, network segmentation, rate limits, WAF |
| Audit-log tampering | Append-oriented application service; state transitions audited | Separate write-only sink, hash chaining, retention lock, external export |
| Privilege escalation | No local endpoint privilege path; no arbitrary commands | Least-privilege roles, scoped service identities, two-person approval |
| Stored-content attacks | React escaping and typed JSON responses | CSP, output encoding review, attachment isolation |
| Resource exhaustion | Bounded string fields and query limits | Request-size limits, quotas, queues, database capacity controls |

## Security invariants

- Event input is never interpreted as code or a shell command.
- Correlation and recommendations are deterministic and explainable.
- Endpoint remediation cannot be invoked in Phase 1.
- Secrets must not be committed and are loaded only from environment variables.
- Browser origins default to the single configured local frontend.

Phase 1 authentication is suitable only for trusted local development. Do not expose the service to an untrusted network without the production follow-ups above.
