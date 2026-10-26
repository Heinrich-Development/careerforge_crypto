<div align="center">

<img src="doc/logo.png" alt="" width="96">

# careerforge_crypto

**The key hierarchy and envelope format behind CareerForge's claim that its
server cannot read your CV.**

</div>

<p align="center">
  <a href="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml"><img src="https://github.com/Heinrich-Development/careerforge_crypto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue.svg" alt="Licence: Apache-2.0"></a>
</p>

[CareerForge](https://careerforge.app) is a CV builder that keeps what you
write encrypted in your browser, so that the server stores only ciphertext it
cannot open. This package is the part of it worth reading if you are deciding
whether to believe that.

## What this is, and what it is not

This repository holds four things: the key hierarchy that turns a password
into keys, the recovery code that is the second way in, the envelope format
every sealed byte is stored in, and a pure-Dart reference engine for the two
primitives underneath. It has two dependencies, `pointycastle` (Argon2id,
AES-GCM) and `crypto` (HMAC-SHA256), and nothing in it can open a socket, read
a file or reach a platform channel. It is a separate package on purpose: a
package boundary is what stops it quietly acquiring a dependency that could
carry a key off the device.

Not in this repository: the browser engine the app runs in production
(WebCrypto, and Argon2 in WebAssembly), the CareerForge app itself, and its
server.

A browser-delivered app is only as trustworthy as the bundle it is served,
and nothing in this repository can prove what that bundle contains. What it
can do is let the *format* and the *reference answers* be checked
independently of the bundle. The browser engine is held to the same vectors as
the reference engine here, and everything above those primitives is the code
in this repository. That check is run by hand whenever the browser engine's
Argon2 build changes; there is no automated cross-engine test today, and that
is a gap worth naming.

## Threat model

**What the server holds.** An Argon2id hash, with a server-side pepper, of a
value derived from the password — never the password itself; a plain SHA-256
of the recovery code's verifier, which is itself a one-way function of 160
random bits; the wrapped copies of the key that content is encrypted under,
with the salt and Argon2id parameters the password copy was derived with;
ciphertext; and plaintext metadata. The metadata is what storing and billing
need: row ids and the links between them, ordering, timestamps, version
counters, byte lengths and counts, the account's email address, plan and
billing state, and for each CV its template, target region, document language
and whether it carries a photo. The server can see how many experiences you
have and in what order. It cannot read one.

**What a leaked database yields** depends on the password. The salt, the
parameters and the password-wrapped key are all in it, so an attacker can
guess passwords offline at the cost of one Argon2id derivation (64 MiB, three
passes) per guess, and a weak password falls to that. A strong one does not,
and the recovery-code path cannot be searched at all: 160 random bits, with
nothing to stretch. The pepper protects only the login verifier, not the
wrapped keys.

**What leaves the browser readable.** When you run an AI feature, the text it
works on — with names, contact details and other identifiers stripped by the
app before it is sent — passes through the server to the AI vendor for that
one request. A compromised server could read those requests as they pass; it
still cannot read anything it stores. Nothing else a person writes leaves the
browser except as ciphertext.

**The limit no format can remove** is the bundle itself. A server that serves
a malicious app can have that app read what you type, and it can do so to one
person at a time. A public security page with the full picture, including the
AI vendors, is forthcoming at [careerforge.app](https://careerforge.app).

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
                        wrapped copies — one per unlock method.
```

The server Argon2id-hashes the submitted `authKey` again, with a server-side
pepper, and stores that. So what it holds is a verifier for a value that is
itself a one-way function of the password, and nothing it holds — verifier,
wrapped keys, ciphertext — leads back to `encKey`.

HKDF-**Expand** only, with the master key used directly as the pseudorandom
key. Extract exists to condense a non-uniform secret; the input here is already
a uniform 32-byte Argon2id output, so extracting again would be an HMAC that
adds nothing.

The indirection through a random `userKey` is what makes a password change a
re-wrap of 32 bytes rather than a re-encryption of the whole Vault (the
person's master record — contact details, experiences, skills and so on —
from which every CV is drafted), and what lets a password and a recovery code
— and, later, a passkey — unlock the same data.

## The recovery code

The second way in, and the reason a forgotten password is not the end of the
data:

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

The same split as the password, and the same guarantee: the value the server
holds proves someone knows the code without opening anything.

**No Argon2id here, deliberately.** Stretching exists to buy entropy a human
password does not have. This value is 160 bits straight from a CSPRNG, so
there is nothing to search offline and a KDF would add nothing — and it has to
work in the one flow where the account's KDF parameters cannot be fetched,
because the client cannot log in to fetch them.

`0123456789ABCDEFGHJKMNPQRSTVWXYZ` — RFC 4648's alphabet without `I`, `L`, `O`
and `U`. 20 bytes is 160 bits, an exact multiple of five, so it encodes to 32
characters with no padding and prints as eight groups of four. Parsing accepts
any case, ignores the separators, and reads `I` and `L` as `1` and `O` as `0`;
`U` is a typo rather than an alias. Being ASCII by construction, a recovery
code cannot be typed in two byte-different ways that look the same — the
Unicode gap below does not reach it.

The code itself never leaves the device. Only the verifier does, and only
during a reset. `RecoveryCode.toString()` is redacted for the same reason.

## The envelope

Every sealed byte in the product has this shape:

```text
  +---------+----------+----------------------------+
  | 1 byte  | 12 bytes | n bytes                    |
  | version | nonce    | ciphertext || 16-byte tag  |
  +---------+----------+----------------------------+
```

AES-256-GCM. Three decisions, each load-bearing:

**The version byte, always.** Rotating the user key or changing cipher is a
client-side migration over rows the server cannot read. The only way a future
client can tell what it is holding is if the byte was there from the first row
ever written. One byte, and it is the difference between a migration and a
rewrite.

**A random nonce per record, not a counter.** A counter needs state shared
across tabs, devices and offline edits, all of which write concurrently — and
a repeated nonce under one key breaks GCM outright.

**Every seal is bound to a domain**, passed to GCM as additional authenticated
data (`careerforge.v1.<domain>`). Without it, ciphertext valid in one slot is
valid in every slot under the same key: a wrapped user key could be written
over a Vault row and the tag would still verify. The domain is not stored —
the reader knows which slot it is reading, and a mismatch simply fails to open.

Domain strings are storage identifiers, not labels. Renaming one makes every
row in that slot permanently unopenable.

For tables holding many rows per user, the domain alone is not enough: two
rows of one table share a key and a table domain, so a server swapping their
content columns would produce rows that still verify. Those rows seal under
`EnvelopeDomain.forEntity(tableDomain, entityId)` — the row's own id folded
into the authenticated data — so a moved content column simply stops
opening. The id is the immutable part of a row and the only part bound; the
mutable plaintext columns beside it (position, a skill's category) stay
outside the AAD so reordering never re-encrypts.

## The engine seam

`CryptoEngine` covers two primitives and nothing else: Argon2id, and AES-GCM
seal/open. Everything else — the envelope, the HKDF split, the hierarchy — is
plain Dart here, identical everywhere and testable on the VM.

`PureDartCryptoEngine` is the reference implementation. The CareerForge app
registers a browser engine instead, which runs Argon2 in WebAssembly and
AES-GCM through WebCrypto, because pure-Dart Argon2id compiled to JavaScript is
far too slow to unlock with. Keeping the seam this narrow means a second
implementation has to agree on *primitives*, which have published test vectors,
rather than on a format it could get subtly wrong.

## Verifying it yourself

```bash
dart pub get
dart test
```

`dart run example/main.dart` walks the whole path once: derive, wrap, seal,
open, and fail to open under the wrong domain.

The published vectors are the ones that matter:

| Vector | What it proves |
|---|---|
| RFC 9106 §5.3 | the primitive really is Argon2id at version 0x13, and `memoryKiB`/`iterations`/`parallelism` map onto the parameters they claim to |
| RFC 5869 A.1 | HKDF-Expand is HKDF-Expand |
| NIST CAVP | AES-256-GCM is AES-256-GCM |

Beside them are the self-generated vectors, labelled as such in the tests: a
fixed password and salt with their expected master key and Argon2 output, and
a fixed recovery code with its expected bytes, encKey and verifier. They prove
nothing about the algorithms — the published vectors do that — and exist so
a second implementation can be held to the same answers. **If one of these
values changes, every existing account is locked out of whichever door it
belongs to.**

## Known gaps

**Passwords are not Unicode-normalised.** Dart has no normalisation in its core
libraries, and adding a dependency to this package is a decision with a higher
bar than convenience. The effect: a password typed with a composed accent and
the same password typed with a combining one derive different keys, so someone
who changes keyboard or platform between setting and entering a password could
be locked out. Worth fixing before non-ASCII passwords are common; recorded
here rather than left to be discovered.

**Key material is never zeroized, and on this platform cannot be.** The
password arrives as a `String`, which is immutable; the master key, encKey,
userKey and recovery bytes are `Uint8List`s on a managed heap that the garbage
collector is free to copy and free to leave behind. Nothing here can promise a
secret is gone from memory once it is finished with. What is done instead is
scope: every one of those values is a local, or a field the app clears on
sign-out; none is written to storage in the clear, and the browser process holding them
ends when the tab does. An attacker who can read this process's memory has
already won by other means — but a document that lists one gap implies the
list is complete, so this is the second one.

**Domain and label strings are ASCII, and enforced rather than assumed.** See
`lib/src/ascii.dart`: a string folded into authenticated data is turned into
bytes one code unit at a time, which silently truncates anything above `0xff`,
so two entity ids differing only above bit 8 would seal under identical AAD.
The check turns that into a refusal instead of a collision. Every value written
to date is ASCII, so enforcing it changed no stored bytes.

## Where this is developed

This repository is a read-only mirror of the `careerforge_crypto/` directory
in CareerForge's private monorepo, synced automatically on every merge to its
main branch, and identical to it except for one `resolution: workspace` line
in `pubspec.yaml`. Issues are welcome here. A pull request here will be
applied in the monorepo by hand and credited in the commit, and then appears
here through the next sync.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md) or email
support@careerforge.app.

## Licence

Apache-2.0; see [LICENSE](LICENSE).
