# QuietWard event protocol v1

Version 1 defines the event contract between untrusted sensors and QuietWard Response. `source` identifies the producer; it is not restricted to QuietWard.

## Compatibility contract

- Producers must send `schema_version: "1.0"` and the required fields in the JSON Schema.
- Consumers accept additional keys inside `evidence`, `process`, `file`, `network`, `persistence`, and `metadata`, so sensors can add evidence without changing the envelope.
- Optional envelope fields may be added in a backwards-compatible v1 minor release. Existing required fields will not change meaning or become optional.
- Breaking field removals, type changes, or semantic changes require a new major schema file and a parallel ingestion path.
- `event_id` is a globally unique UUID and is the idempotency key. Reusing it is rejected, even if the payload differs.
- Timestamps are RFC 3339 UTC offsets. Naive timestamps are rejected.

Sensors are untrusted. Schema validation is necessary but not sufficient: deployments should authenticate sources, rate-limit ingestion, prevent replays, and constrain source-to-host authorization before accepting internet traffic.
