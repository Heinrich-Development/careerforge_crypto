<div align="center">

<img src="doc/logo.png" alt="" width="96">

# careerforge_crypto

**The encryption used to protect CV data in CareerForge.**

</div>

<p align="center">
  <a href="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml"><img src="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue.svg" alt="Licence: Apache-2.0"></a>
</p>

This repository contains the Dart reference implementation of the encryption
used by [CareerForge](https://careerforge.app).

CareerForge encrypts CV content in the browser before storing it on the
server. The server can store and sync the data without having the keys
needed to decrypt it. This package covers the key hierarchy, password-based
key derivation, recovery codes, and the format used to encrypt and decrypt
data. I've made it public so the encryption format can be inspected and
tested independently of the main application.

The implementation uses `pointycastle` for Argon2id and AES-GCM, and
`crypto` for HMAC-SHA256. It has no networking, file I/O or platform
integrations, and it is a separate package so that adding a dependency is a
visible decision rather than something that happens in passing.

The CareerForge application, its backend and the production browser
implementation are not part of this repository. The browser implementation
uses WebCrypto and Argon2 in WebAssembly, and is currently checked by hand
against the test vectors here. Automated cross-implementation testing is
something I still want to add.

## Threat model

**Encrypted data.** Everything a person writes: contact details, work
history, skills, the photo, drafts, cover letters, the application board and
the pasted job ads. All of it is stored as AES-256-GCM ciphertext under a key
the server never sees.

**Visible metadata.** Row ids and the links between them, ordering,
timestamps, version counters, sizes and counts, the account's email address,
plan and billing state, and for each CV its template, target region,
language and whether it has a photo. The server can see how many job entries
exist, but not their contents.

**Authentication data.** A peppered Argon2id hash of a value derived from
the password (never the password itself), a SHA-256 of the recovery code's
verifier, and the wrapped copies of the content key along with the salt and
Argon2id parameters they were derived with.

A leaked database would allow offline password guessing, at the cost of one
Argon2id derivation (64 MiB, three passes) per guess, which is why password
strength still matters. The recovery code is 160 random bits and cannot be
guessed this way.

AI features are the exception to "the server never sees content". When a
person runs one, the text it works on is sent through the server to the AI
vendor, with names and contact details stripped first. The server handles
that text in memory for the duration of the request and does not store it.

There is one limitation no format can remove: the frontend itself still
needs to be trusted. A browser app is only as trustworthy as the code it is
served, and a malicious bundle could read what the person types. This
package lets the format be checked independently of the bundle, which is as
far as a format can go. A security page with the full picture is coming at
careerforge.app.

## Key hierarchy

```text
  password + kdfSalt
        |  Argon2id  (m=64 MiB, t=3, p=1 by default; stored per account)
        v
    masterKey ......... 32 bytes. Never stored, never transmitted.
        |
        +-- HKDF-Expand "careerforge.enc"  --> encKey
        |                                      wraps the userKey, never leaves
        |                                      the device
        |
        +-- HKDF-Expand "careerforge.auth" --> authKey
                                               base64url, sent as the password

    userKey ........... 32 random bytes. Encrypts all content. Stored only as
                        wrapped copies, one per unlock method.
```

The server hashes the submitted `authKey` again with Argon2id and a
server-side pepper, and stores that. Nothing the server holds leads back to
`encKey`.

Content is encrypted under a random `userKey` rather than under the master
key directly. A password change then only re-wraps 32 bytes instead of
re-encrypting everything, and a password and a recovery code can both unlock
the same data.

## Recovery code

```text
  recoveryCode ...... 20 random bytes, Crockford base32, shown once
        |
        +-- HKDF-Expand "careerforge.recovery.enc"    --> encKey
        |                                                 wraps the userKey
        |
        +-- HKDF-Expand "careerforge.recovery.verify" --> verifier
                                                          base64url, sent
                                                          during a reset
```

The recovery code uses the same split as the password, but without Argon2id.
Stretching compensates for the low entropy of human passwords, and this
value has 160 bits from a CSPRNG, so there is nothing to compensate for. It
also has to work during a reset, when the account's KDF parameters cannot be
fetched because the person cannot log in.

The code is 32 characters from `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, shown in
groups of four. Parsing ignores case and separators, and reads `I` and `L`
as `1` and `O` as `0`. The code itself never leaves the device; only the
verifier is sent, during a reset.

## Envelope format

```text
  +---------+----------+----------------------------+
  | 1 byte  | 12 bytes | n bytes                    |
  | version | nonce    | ciphertext || 16-byte tag  |
  +---------+----------+----------------------------+
```

AES-256-GCM. Three decisions worth explaining:

- **A version byte on every envelope.** Changing the key or the cipher
  later means a client-side migration over rows the server cannot read, and
  the version byte is how a future client knows what it is looking at.
- **A random nonce per record.** A counter would need state shared across
  tabs, devices and offline edits, and a repeated nonce under one key breaks
  GCM.
- **A domain in the authenticated data** (`careerforge.v1.<domain>`). This
  stops ciphertext from one slot being accepted in another. For tables with
  many rows per user, the row's own id is included as well
  (`EnvelopeDomain.forEntity`), so a content column moved to another row
  fails to decrypt. The domain is not stored; the reader knows which slot it
  is reading. Because of this, renaming a domain string would make every row
  in that slot unreadable.

## Crypto engines

`CryptoEngine` is a small interface covering Argon2id and AES-GCM seal/open.
Everything above it, the envelope, the HKDF split and the key hierarchy, is
plain Dart shared by every implementation. `PureDartCryptoEngine` is the
reference. The app's browser engine replaces it in production because
pure-Dart Argon2id compiled to JavaScript is far too slow for an unlock. A
second engine only has to agree on primitives with published test vectors,
not on a format it could get subtly wrong.

## Running the tests

```bash
dart pub get
dart test
dart run example/main.dart
```

The published vectors are:

| Vector | What it checks |
|---|---|
| RFC 9106 §5.3 | the Argon2id implementation (version 0x13) and the parameter mapping |
| RFC 5869 A.1 | the HKDF-Expand implementation |
| NIST CAVP | the AES-256-GCM implementation |

The repository also includes test vectors with fixed passwords, salts and
recovery codes. These are not independent checks of the underlying
algorithms, but they ensure that different implementations produce the same
results, which matters for compatibility with existing encrypted data.

## Known gaps

- **Passwords are not Unicode-normalised.** A composed and a combining
  accent derive different keys.
- **Key material is never zeroized.** Dart strings are immutable and the
  heap is garbage collected, so there is no reliable way to wipe a key. Keys
  live in locals or in fields the app clears on sign-out, and nothing is
  written to storage in the clear.
- **Domain and label strings must be ASCII.** The encoding would silently
  truncate anything above `0xff`, so the package refuses non-ASCII input
  instead.
- **No automated cross-engine test.** The browser engine is checked against
  the vectors here by hand when its Argon2 build changes.

## Where this is developed

This repository is a read-only mirror of the `careerforge_crypto/` directory
in CareerForge's private monorepo, synced on every merge to main. It is
identical apart from one `resolution: workspace` line in `pubspec.yaml`.
Issues are welcome here. A pull request will be applied in the monorepo by
hand, credited, and will arrive with the next sync.

## Security

See [SECURITY.md](SECURITY.md), or email support@careerforge.app.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
