# Changelog

## 1.0.0 - 2026-10-26

The first public release, and the point from which the format is frozen.
Each of the following is part of what is already stored, so changing any of
them would make existing data or existing accounts unopenable:

- The envelope layout and its format version byte, `0x01`.
- Every `EnvelopeDomain` string, the `careerforge.v1.` prefix they are
  authenticated under, and the `forEntity` rule (`<domain>:<entityId>`).
- The HKDF labels: `careerforge.enc`, `careerforge.auth`,
  `careerforge.recovery.enc` and `careerforge.recovery.verify`.
- The recovery code: 20 bytes, Crockford base32
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), 32 characters.
- The self-generated vectors in `test/`.

Two engines implement `CryptoEngine`: `PureDartCryptoEngine`, the reference,
here; and the browser engine (WebCrypto, and Argon2 in WebAssembly), which
lives in the CareerForge app and has to give the same answers.
