# QuietWard Response event protocol

Version `1.0` is the first stable event envelope between sensors and QuietWard Response. QuietWard may implement this protocol later, but neither project imports or embeds the other.

## Compatibility contract

- Producers must send a supported `schema_version`; unsupported major versions fail closed.
- Fields required by v1 will remain required for the lifetime of the v1 major version.
- New optional fields may be added without changing the major version. Consumers must ignore unknown nested evidence keys, but the top-level envelope remains strict.
- Breaking changes require a new schema file and major version, with an explicit migration and overlap period.
- `event_id` is a UUID and is globally idempotent. Replays of an accepted ID return `409 Conflict` and are audited.
- Timestamps must be timezone-aware RFC 3339 values. The server normalizes them to UTC.

The protocol deliberately carries observations and evidence, not endpoint commands. A future action protocol will be separately versioned, authenticated, policy-gated, and replay-resistant.
