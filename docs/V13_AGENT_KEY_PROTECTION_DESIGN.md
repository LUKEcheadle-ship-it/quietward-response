# QuietWard Response v1.3 agent-key protection design

Status: **design contract — not implemented in v1.2**

## Problem

The v1.2 HMAC protocol is strongly scoped on the wire, but HMAC verification is symmetric: the Response server must possess credential-equivalent key material for the active agent credential (and briefly for a staged replacement). A database disclosure that includes those usable verification keys can therefore enable forged agent signatures.

v1.2 reduces exposure by never returning verification material through normal APIs, never logging it, never retaining retired HMAC material, using immediate old-key revocation, and keeping pending replacement credentials short-lived. It does **not** solve symmetric-key-at-rest risk.

## Security objective

A database-only compromise must not be sufficient to forge authenticated Response-agent traffic.

Any v1.3 implementation must preserve:

- agent-initiated outward communication only;
- method/path/query/timestamp/nonce/body binding;
- replay protection;
- exact agent/host binding;
- capability attestation;
- action-result authentication;
- key rotation and explicit revocation;
- fail-closed startup/deployment behavior;
- no generic remote command surface.

## Preferred architecture: asymmetric endpoint signatures

The preferred long-term design is per-agent asymmetric signing rather than reversible server-side storage of HMAC secrets.

### Enrollment

1. Response creates a short-lived one-time enrollment authorization.
2. The Response agent generates its private signing key **locally**.
3. The private key never leaves the endpoint.
4. Enrollment submits only the public verification key plus host/agent metadata.
5. Response stores the public key, key identifier, algorithm/version and lifecycle metadata.
6. Enrollment proof binds the public key to the one-time authorization so an attacker cannot substitute another key during enrollment.

### Request signatures

A versioned canonical message must continue to bind:

- protocol version;
- HTTP method;
- exact path + query;
- timestamp;
- high-entropy nonce;
- SHA-256 request-body digest;
- agent ID;
- key ID.

The signature algorithm should be a widely reviewed modern primitive supported by a vetted library. Ed25519 is a strong candidate where platform/library qualification is satisfactory.

### Rotation

1. current private key signs a request to stage a replacement public key;
2. replacement private key is generated locally;
3. replacement key signs an activation proof;
4. server atomically marks the replacement public key current and the old key revoked;
5. old public key can remain for audit verification/history because it is not secret;
6. no credential-equivalent retired material exists on the server.

### Recovery/revocation

- analyst admin can disable/revoke an agent credential;
- disable clears capability authority and undispatched work as in v1.2;
- recovery enrollment must require a separate explicit enrollment/recovery authorization, not silent server-generated private keys;
- private-key loss must not be bypassed by falling back to an old revoked key.

## Transitional alternative: authenticated encryption at rest

If asymmetric migration is not ready, a transitional v1.3 may encrypt active/pending HMAC verification material with a server secret that is **not stored in the Response database**.

This is acceptable only if all of the following are true:

- uses a vetted authenticated-encryption implementation from a maintained cryptography library;
- no custom cipher/MAC construction;
- independent encryption key supplied by environment/secret manager/OS secret service;
- non-development startup fails closed without a strong replacement key;
- ciphertext is bound with authenticated associated data to agent ID + key ID + purpose/version;
- key rotation/re-encryption is documented and tested;
- database-only compromise cannot recover agent verification material;
- application-secret compromise plus database compromise remains explicitly documented as sufficient to decrypt;
- plaintext legacy records are detectable and prohibited in production after migration;
- migration is reversible operationally without silently downgrading to plaintext.

The transitional encrypted-HMAC design is still weaker than endpoint-held asymmetric private keys because the server remains capable of deriving signing material at runtime.

## Required acceptance tests

### Database compromise model

- database rows contain no agent private key;
- asymmetric design: only public verification key material is present;
- encrypted-HMAC transition: no active/pending plaintext or directly usable HMAC key is present;
- retired credential rows contain no secret material;
- API serialization cannot expose protected key material.

### Authentication

- valid current signature accepted;
- wrong key ID rejected;
- body/path/query tamper rejected;
- stale/future timestamp rejected;
- nonce replay rejected;
- signature from another agent rejected;
- disabled/revoked credential rejected;
- old key rejected immediately after activation;
- staged replacement cannot sign normal traffic before activation.

### Rotation

- one pending rotation at a time;
- replacement proof required;
- interrupted local promotion recoverable without re-enabling old key;
- old credential cannot regain authority after disable/re-enable;
- public/audit metadata never contains private material.

### Storage/key-management failure

- missing production key-management secret fails startup for encrypted-HMAC transition;
- malformed ciphertext fails closed;
- wrong encryption key fails closed;
- tampered ciphertext/AAD fails closed;
- no automatic fallback to plaintext;
- logs/audits never print decrypted key material.

### Cross-platform qualification

- Windows endpoint private-key storage behavior qualified;
- Linux endpoint private-key storage behavior qualified;
- backup/restore behavior documented so server database backup does not accidentally become credential backup;
- endpoint private-key permissions/OS protection verified independently.

## Implementation rule

Do **not** solve this by adding a home-grown encryption routine or by merely base64-encoding/obfuscating the existing HMAC key. A real implementation must use a vetted cryptographic library and must ship with migration, failure, recovery, and adversarial tests before it replaces the v1.2 protocol.

## Release sequencing

1. finish and qualify v1.2 containment/control-plane hardening;
2. choose asymmetric signing vs transitional encrypted HMAC based on target platform/library qualification;
3. implement behind a versioned agent-auth protocol;
4. migrate test agents first;
5. run old/new protocol downgrade and substitution attacks;
6. prohibit legacy symmetric-at-rest mode in production before v1.3 stable.
