# libsignal Security & Reliability Hardening

<p align="center">
  <img src="https://files.catbox.moe/rq5sf4.gif" alt="ChatUnity banner" width="100%" />
</p>

<p align="center">
  <strong>Legacy Signal Protocol v3 implementation — security, correctness and operational hardening notes.</strong>
</p>

> **Status:** This repository is a legacy 1:1 Signal Protocol library. It is **not** a complete WhatsApp Multi-Device or Baileys implementation.

## Overview

This project provides components for legacy Signal Protocol v3-style one-to-one sessions: identity keys, signed pre-keys, one-time pre-keys, X25519 key agreement, session establishment, Double Ratchet state, message encryption/decryption, protobuf frames, and session serialization.

The library is intended to remain isolated from application-specific WhatsApp, Baileys, auth-state, sender-key, and deployment logic. Any production integration must provide a secure external key store, durable persistence, strict concurrency control, and careful secret management.

## Components

| Path | Responsibility |
|---|---|
| `src/keyhelper.js` | Identity keys, signed pre-keys, one-time pre-keys, registration ID |
| `src/curve.js` | X25519 agreement and signed pre-key signing/verification |
| `src/session_builder.js` | Initial outgoing/incoming session establishment |
| `src/session_cipher.js` | Encryption, decryption and Double Ratchet operations |
| `src/session_record.js` | Historical sessions, chains and session serialization |
| `src/crypto.js` | HKDF-like derivation, AES-256-CBC and HMAC-SHA256 |
| `src/queue_job.js` | In-process asynchronous queue by address |
| `src/protocol_address.js` | `user.device` address representation and parsing |
| `src/WhisperTextProtocol.js` | Signal v3 protobuf frames |

## Scope and limits

This codebase does **not** include the following components:

- Baileys socket connection or WhatsApp Web transport
- `creds.update`, `useMultiFileAuthState`, or a Baileys `SignalKeyStore`
- WhatsApp sender keys and group encryption
- App-state synchronization
- A concrete database, encrypted auth-state adapter, backup workflow, or migration system
- Distributed locks, fencing tokens, or multi-node coordination

Do not present this repository alone as a complete WhatsApp Multi-Device implementation. For a production WhatsApp integration, use a maintained and compatible upstream Baileys/libsignal layer plus a properly designed persistence and deployment architecture.

## Security priorities

The following issues must be addressed before treating the library as production-ready.

### SEC-01 — Enforce signed pre-key verification

**Severity:** High  
**Files:** `src/session_builder.js`, `src/curve.js`

A signed pre-key signature must always be verified. Any bypass such as passing a flag that forces `verifySignature()` to return `true` compromises bundle authenticity and can enable denial-of-service during session bootstrap.

**Required behavior:**

- Accept a correctly signed signed pre-key.
- Reject altered signatures, null signatures, altered signed pre-keys, and malformed public keys.
- Remove bypass parameters and verify with the underlying signature verifier on every path.

### SEC-02 — Commit ratchet state only after authentication

**Severity:** High  
**File:** `src/session_cipher.js`

Do not mutate a persisted `SessionRecord` before the incoming frame passes MAC verification and decryption/padding validation. Ratchet transitions, message-key consumption, counters, chains, and pending pre-key state must be computed on a temporary copy.

**Required behavior:**

- Clone the entire session entry before a decrypt attempt.
- Verify MAC and decrypt successfully before replacing the original session state.
- Preserve the original record byte-for-byte when decryption fails.
- Reject invalid ephemeral keys and malformed frames without advancing ratchet state.

### SEC-03 — Make session and pre-key updates atomic

**Severity:** High  
**Files:** `src/session_cipher.js`, external storage adapter

Persisting a session record and consuming a one-time pre-key must be coordinated atomically. A crash between those writes can cause pre-key reuse, message-key loss, or inconsistent session state.

**Required behavior:**

- Build the complete outbound frame before committing the updated session.
- Add a storage-level transaction or compare-and-swap workflow for session state and pre-key consumption.
- Support explicit reservation/consumption semantics for one-time pre-keys.
- Test failure injection after every storage operation.

### SEC-04 — Do not rely on in-process locking for scale

**Severity:** High  
**File:** `src/queue_job.js`

`_queueAsyncBuckets` is only an in-memory queue within a single Node.js process. It does not protect the same account or device from concurrent PM2 workers, containers, or replicas.

**Required behavior:**

- Run a single owner process per account/session, **or** implement a distributed lock with lease and fencing token.
- Use database transactions or optimistic compare-and-swap/version checks for session records.
- Reject or retry conflicting writes safely; never silently overwrite ratchet state.
- Test simultaneous encryption/decryption from two independent processes.

### SEC-05 — Keep WhatsApp MD concerns separate

**Severity:** High  
**Scope:** Entire repository

This library implements legacy 1:1 Signal-style sessions only. It does not provide WhatsApp Multi-Device features such as device fan-out, sender keys, group encryption, app-state sync, credentials, or Baileys transport.

**Required behavior:**

- Keep this repository isolated as a low-level cryptographic component.
- Do not add custom sender-key or WhatsApp Multi-Device logic without a compatible, maintained protocol layer.
- Validate real multi-device and group scenarios only through the actual Baileys integration repository.

### SEC-06 — Provide a secure auth and key-store layer

**Severity:** High  
**Scope:** External application/storage adapter

No concrete credential store, encrypted key persistence, backup/restore flow, or `creds.update` handling is present here. These responsibilities must be implemented in the calling application.

**Required behavior:**

- Persist credentials, session records, pre-keys, and sender keys separately.
- Encrypt sensitive material at rest and protect it with least-privilege ACLs.
- Never log private keys, session records, QR data, pairing codes, tokens, or message payloads.
- Make persistence durable, versioned, transactional where necessary, and testable under crashes and restores.

## Reliability improvements

### Registration ID generation

`generateRegistrationId()` must use both random bytes and produce a non-zero registration ID in the expected range `1..16380`.

```js
exports.generateRegistrationId = function () {
  let randomValue;

  do {
    randomValue = nodeCrypto.randomBytes(2).readUInt16BE(0);
  } while (randomValue >= 65520);

  return (randomValue % 16380) + 1;
};
```

> Do not regenerate a registration ID already stored for an existing identity.

### Strict protocol-address parsing

Address parsing must reject trailing content, invalid device IDs, non-integer IDs, negative values, and malformed identifiers.

```js
static from(encodedAddress) {
  const match = typeof encodedAddress === 'string'
    && /^([^.]+)\.([0-9]+)$/.exec(encodedAddress);

  if (!match) {
    throw new Error('Invalid address encoding');
  }

  return new this(match[1], Number(match[2]));
}
```

The constructor should require `Number.isSafeInteger(deviceId)` and reject negative values.

### Constant-time MAC comparison

Use `crypto.timingSafeEqual()` after validating both lengths.

```js
function verifyMAC(data, key, mac, length) {
  const calculatedMac = calculateMAC(data, key, length);

  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error('Bad MAC length');
  }

  if (!nodeCrypto.timingSafeEqual(Buffer.from(mac), calculatedMac)) {
    throw new Error('Bad MAC');
  }
}
```

### Validate untrusted input

Fail closed when receiving malformed records or frames. Validate at minimum:

- Protocol-address syntax and safe integer device IDs
- Frame presence, length, and internally consistent protocol versions
- Required protobuf fields and their types
- Ephemeral public-key length and format
- Ciphertext length compatible with the cipher mode
- Key lengths, chain shape, counter ranges, and duplicate chains
- Session-record schema version before deserialization

## Session-record format

`SessionRecord` currently uses a project-specific shape such as `_sessions` and `_chains`. Treat it as an internal storage format, not an upstream-compatible interchange format.

Before migrations or restores:

- Add an explicit schema version.
- Validate every field structurally during deserialization.
- Reject truncated JSON, invalid key sizes, negative counters, malformed chains, and duplicate open sessions.
- Implement explicit migration steps instead of implicit format guessing.
- Encrypt and authenticate records at rest in the external storage adapter.
- Fail closed on ambiguous or corrupted state; do not regenerate identity keys automatically.

If multiple open sessions exist for the same address, reject the record as inconsistent rather than selecting the first entry. When pruning closed sessions, scan all sessions and remove the intended oldest closed record deterministically.

## Dependency hygiene

Keep `package.json` and the lockfile aligned. A manifest requesting one `protobufjs` version while the lockfile resolves another makes builds non-reproducible.

Recommended workflow:

```bash
# Select one dependency version, then regenerate and verify one lockfile.
yarn install --frozen-lockfile
npm audit --omit=dev
npm audit
npm test
```

Additional requirements:

- Pin dependencies and Git commits where applicable.
- Review `preinstall`, `install`, and `postinstall` scripts.
- Use secret scanning, software composition analysis, and an SBOM in CI.
- Review old cryptographic dependencies carefully before upgrades.
- Update vulnerable development tooling separately and validate lint/build/test compatibility.
- Do not install unverified forks or packages merely to resolve a libsignal-related error.

## Storage contract

The application-provided store should support a contract equivalent to the following:

```ts
interface SecureSignalStore {
  getSession(address: string): Promise<SessionRecord | undefined>;
  compareAndSwapSession(
    address: string,
    expectedVersion: number,
    nextRecord: SessionRecord
  ): Promise<boolean>;

  reservePreKey(preKeyId: number): Promise<ReservedPreKey>;
  commitSessionAndConsumePreKey(input: {
    address: string;
    expectedVersion: number;
    nextRecord: SessionRecord;
    preKeyReservation?: ReservedPreKey;
  }): Promise<void>;

  getIdentityKey(): Promise<Buffer>;
  isTrustedIdentity(id: string, key: Buffer): Promise<boolean>;
}
```

The exact API may differ, but the required properties remain the same: durable writes, version/conflict detection, atomic pre-key consumption, strict secret handling, and no concurrent owner without coordination.

## Operational hardening

### Local development

- Never commit auth state, session data, private keys, QR data, pairing data, or backups.
- Add `.env*`, session directories, backup directories, and local databases to `.gitignore`.
- Run secret scanning before every push.
- Use synthetic test keys and test fixtures only.

### Docker

- Mount secrets and persistent state from a secret manager or protected volume; do not bake them into image layers.
- Give each account/session a private volume.
- Do not share auth/key volumes between unrelated containers.
- Encrypt backups and test restoration in an isolated environment.

### PM2 and Linux

- Do not use PM2 cluster mode for the same account/session without distributed coordination.
- Prefer one worker per account, or implement leases plus fencing tokens.
- Run the process under a dedicated non-root user.
- Use directory permissions `0700` and sensitive-file permissions `0600`.
- Consider systemd hardening such as `ProtectSystem`, `PrivateTmp`, and `NoNewPrivileges`.

### Database

- Require TLS, encryption at rest, least-privilege access, and audited access paths.
- Use transactions or optimistic concurrency controls per account/device.
- Version schemas and migrations; do not overwrite cryptographic state automatically.
- Never restore the same account backup concurrently into multiple active workers.

### Logging and metrics

Redact all sensitive values before output. Logs should contain only a hashed account identifier, device ID when safe, classified error type, timestamp, and correlation ID.

Track at minimum:

- MAC failures
- Decryption failures
- Session resets
- Missing sessions
- Pre-key inventory and consumption failures
- Sender-key errors in the external WhatsApp layer
- Auth/key persistence failures
- Storage latency and transaction conflicts
- Reconnect loops in the external transport layer

Do not retry cryptographic failures indefinitely. Use bounded exponential backoff only for demonstrably transient storage or transport failures.

## Test plan

### Baseline

```bash
npm install --ignore-scripts --no-package-lock --no-audit --no-fund
npx eslint index.js src/*.js
npm audit --omit=dev
npm audit
npm test
```

The project should define an actual test script before release. Lint, production dependency audit, full toolchain audit, and interoperability tests should run in CI.

### Unit tests

- Generate identity keys and validate expected lengths.
- Accept a valid signed pre-key signature.
- Reject altered, null, truncated, and malformed signed pre-key signatures.
- Generate one-time pre-keys with valid unique IDs.
- Generate 10,000 registration IDs; every value must be within `1..16380` and never zero.
- Validate correct, altered, and truncated MAC values.
- Reject invalid or low-order X25519 public keys and all-zero shared secrets.
- Parse valid addresses and reject trailing data, negative IDs, fractional IDs, and unsafe integers.
- Serialize and deserialize valid session records.
- Reject corrupt JSON, wrong key lengths, invalid counters, malformed chains, and duplicate open sessions.

### Integration tests

- Create isolated Alice and Bob stores.
- Exchange the initial pre-key message.
- Exchange subsequent messages for the same device.
- Process out-of-order messages within the supported skipped-key limit.
- Perform bidirectional ratchet updates.
- Maintain separate sessions for the same user across multiple devices.
- Handle a backlog for a closed historical session.
- Test group sender keys only in the real, compatible WhatsApp/Baileys layer.

### Atomicity and crash tests

Inject failures at every write boundary:

- Before and after session persistence
- Between session persistence and pre-key removal
- During registration-ID retrieval
- While storage is read-only or temporarily unavailable
- During timeout/retry handling

Success criteria:

- No one-time pre-key becomes reusable after a successful committed session setup.
- No session state advances without a fully produced outbound frame.
- A failed decrypt leaves the session record unchanged.
- Every persisted record remains deserializable.

### Concurrency tests

Run two independent processes against the same account/device:

- Two simultaneous encrypt operations
- Duplicate simultaneous decrypt operations
- Simultaneous credential/key-store updates

Success criteria: no lost update, no corrupted record, deterministic conflict handling, and no silent overwrite of ratchet state.

### Restart and restore tests

- Restart during credential/key persistence.
- Restart after a ratchet step.
- Restart after receiving a message but before external acknowledgement.
- Restore a consistent backup.
- Reject or explicitly migrate old-version backups.

Regression indicators include increased `Bad MAC` errors, missing sessions after restart, inconsistent pre-key counts, unexpected identity-key changes, duplicate open sessions, reconnect loops, and competing writers for the same cryptographic state.

## Safe implementation order

1. Remove all signed pre-key signature bypasses.
2. Prevent any ratchet/session mutation before successful authentication and decryption.
3. Add atomic session/pre-key storage semantics.
4. Enforce one active owner or distributed concurrency control per account/session.
5. Align dependency manifest and lockfile; establish reproducible CI installs.
6. Fix registration-ID generation and strict input validation.
7. Version and validate session-record serialization before migrations or restores.
8. Add classified, redacted observability and the full test suite.
9. Integrate only with a maintained, compatible Baileys/WhatsApp layer when required.

## Security notice

This software handles highly sensitive cryptographic material. Protect identity keys, signed pre-keys, one-time pre-keys, session records, credentials, backups, and database snapshots as secrets.

Do not weaken cryptographic checks, alter the Signal Protocol to bypass compatibility or enforcement mechanisms, or treat throttling as a way to evade platform controls. For customer-facing, proაქტive, or commercial WhatsApp messaging, use the official WhatsApp Business Platform and obtain explicit user consent.

## Developed by

Developed by **ChatUnity**.

## Credits

This project is based on concepts and legacy foundations from **WhisperSystems / Signal Protocol**. Credit goes to the original WhisperSystems implementation and the wider Signal Protocol ecosystem.