<div align="center">

<img src="doc/logo.png" alt="" width="96">

# careerforge_crypto

**The encryption behind CareerForge's claim that its server cannot read
your CV.**

</div>

<p align="center">
  <a href="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml"><img src="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue.svg" alt="Licence: Apache-2.0"></a>
</p>

[CareerForge](https://careerforge.app) encrypts what you write in your
browser, and the server stores ciphertext it cannot open. This package is
the part worth reading if you want to check that: the key hierarchy, the
recovery code, the envelope format, and a pure-Dart reference engine.

It depends on `pointycastle` (Argon2id, AES-GCM) and `crypto` (HMAC-SHA256)
and nothing else. Nothing here can open a socket, read a file or reach a
platform channel, and the package boundary keeps it that way.

Not in this repository: the app, the server, and the browser engine the app
uses in production (WebCrypto, with Argon2 in WebAssembly). That engine is
checked against the vectors here by hand when its Argon2 build changes.
There is no automated cross-engine test yet.

## Threat model

**The server holds** a peppered Argon2id hash of a value derived from your
password, a SHA-256 of the recovery code's verifier, the wrapped copies of
your content key with their salt and parameters, ciphertext, and plaintext
metadata: ids, ordering, timestamps, sizes and counts, your email, plan and
billing state, and each CV's template, target region, language and whether
it has a photo. It can see how many jobs you have listed. It cannot read
one.

**A leaked database** lets an attacker guess passwords offline, at one
Argon2id derivation (64 MiB, three passes) per guess. A weak password falls
to that. A strong one does not, and the recovery code cannot be guessed at
all: 160 random bits.

**AI features** send the text they work on through the server to the AI
vendor, with names and contact details stripped first. A compromised server
could read those requests in flight. It still cannot read anything it
stores.

**The limit** is the bundle. A browser app is only as trustworthy as the
code it is served, and a malicious bundle can read what you type. This
package lets you check the format independently of the bundle, which is the
most a format can do. A security page with the full picture is coming at
careerforge.app.

## The hierarchy

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

The server hashes the submitted `authKey` again, with a server-side pepper,
and stores that. Nothing it holds leads back to `encKey`.

Content is encrypted under a random `userKey` rather than the master key, so
a password change re-wraps 32 bytes instead of re-encrypting everything, and
a password and a recovery code can unlock the same data.

## The recovery code

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

The same split as the password, without Argon2id: stretching makes up for
the entropy a human password lacks, and this value has 160 bits from a
CSPRNG. It is 32 characters from `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, shown
in groups of four. Parsing ignores case and separators, and reads `I` and
`L` as `1` and `O` as `0`. The code never leaves the device.

## The envelope

```text
  +---------+----------+----------------------------+
  | 1 byte  | 12 bytes | n bytes                    |
  | version | nonce    | ciphertext || 16-byte tag  |
  +---------+----------+----------------------------+
```

AES-256-GCM, with three decisions behind it:

- **A version byte**, so a future client can tell what it is holding when
  it migrates rows the server cannot read.
- **A random nonce per record.** A counter would need state shared across
  tabs, devices and offline edits.
- **A domain in the authenticated data** (`careerforge.v1.<domain>`), so
  ciphertext valid in one slot is not valid in another. Rows in a
  multi-row table fold their own id in as well
  (`EnvelopeDomain.forEntity`), so a content column moved to another row
  stops opening. Renaming a domain string makes every row in that slot
  unopenable.

## The engine seam

`CryptoEngine` covers Argon2id and AES-GCM seal/open, nothing else.
Everything above it is plain Dart. `PureDartCryptoEngine` is the reference;
the app's browser engine replaces it because pure-Dart Argon2id compiled to
JavaScript is far too slow. A second engine only has to agree on primitives
with published test vectors, not on a format it could get subtly wrong.

## Verifying it yourself

```bash
dart pub get
dart test
dart run example/main.dart
```

| Vector | What it proves |
|---|---|
| RFC 9106 §5.3 | the primitive is Argon2id v0x13, and the parameters mean what they say |
| RFC 5869 A.1 | HKDF-Expand is HKDF-Expand |
| NIST CAVP | AES-256-GCM is AES-256-GCM |

The self-generated vectors beside them (a fixed password, salt and recovery
code with their expected outputs) prove nothing about the algorithms. They
exist so a second implementation can be held to the same answers. **If one
of them changes, every existing account is locked out of that door.**

## Known gaps

- **Passwords are not Unicode-normalised.** A composed and a combining
  accent derive different keys.
- **Key material is never zeroized.** Dart strings are immutable and the
  heap is garbage collected. Keys live in locals or in fields the app clears
  on sign-out, and nothing is written to storage in the clear.
- **Domain and label strings must be ASCII**, and the package refuses
  otherwise, because the encoding would silently truncate anything above
  `0xff`.

## Where this is developed

This is a read-only mirror of the `careerforge_crypto/` directory in
CareerForge's private monorepo, synced on every merge to main and identical
apart from one `resolution: workspace` line in `pubspec.yaml`. Issues are
welcome here. A pull request will be applied in the monorepo by hand,
credited, and arrive with the next sync.

## Security

See [SECURITY.md](SECURITY.md), or email support@careerforge.app.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
