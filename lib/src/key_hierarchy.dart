import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'crypto_engine.dart';
import 'envelope.dart';
import 'hkdf.dart';
import 'exceptions.dart';
import 'kdf_params.dart';

/// Everything derived from a password, and the one key everything is encrypted
/// under.
///
/// ```text
///   password + kdfSalt
///         |  Argon2id
///         v
///     masterKey (32 bytes, never stored, never sent)
///         |
///         +-- HKDF "careerforge.enc"  --> encKey   wraps the userKey
///         |
///         +-- HKDF "careerforge.auth" --> authKey  sent as the "password"
///
///     userKey (32 random bytes) -- encrypts every piece of content, and is
///     stored only as wrapped copies, one per unlock method.
/// ```
///
/// The split is the whole trick. The server receives [deriveAuthKeyString] and
/// hashes it again with its own Argon2id and a server-side pepper, so what it
/// stores is a verifier for a value that is itself a one-way function of the
/// password. Nothing the server holds -- verifier, wrapped keys, ciphertext --
/// leads to encKey, and therefore nothing leads to content.
///
/// The indirection through a random [generateUserKey], rather than encrypting
/// under encKey directly, is what makes a password change a re-wrap of 32 bytes
/// instead of a re-encryption of the whole vault -- and what lets a passkey and
/// a recovery code unlock the same data by wrapping the same key a second and
/// third time.
abstract final class KeyHierarchy {
  /// HKDF label for the key that wraps the user key. A storage identifier:
  /// changing it makes every wrapped key unopenable.
  static const String _encInfo = 'careerforge.enc';

  /// HKDF label for the value sent to the server.
  static const String _authInfo = 'careerforge.auth';

  /// Bytes in the master key, encKey, authKey and userKey alike: 256 bits,
  /// AES-256's key size.
  static const int keyLength = 32;

  /// Recommended salt length. Per account, plaintext, stored beside the
  /// account row.
  static const int saltLength = 16;

  /// Argon2id over the password. The expensive step, and the only one.
  ///
  /// Rejects parameters below [KdfParams.meetsMinimum]: they arrive from the
  /// server, and a client that derived at whatever cost it was handed would let
  /// a compromised server turn every password into a cheap one.
  /// `async` so that a rejected parameter arrives as a failed future rather
  /// than a synchronous throw. A method returning a [Future] that sometimes
  /// throws before returning one is the kind of thing a caller only discovers
  /// when its try/catch does not fire.
  static Future<Uint8List> deriveMasterKey({
    required CryptoEngine engine,
    required String password,
    required Uint8List salt,
    required KdfParams params,
  }) async {
    if (!params.meetsMinimum) {
      throw CryptoFormatException(
        'Refusing to derive with $params: below the OWASP Argon2id minimum.',
      );
    }
    if (salt.length < 8) {
      throw const CryptoFormatException('KDF salt must be at least 8 bytes.');
    }

    return engine.argon2id(
      password: Uint8List.fromList(utf8.encode(password)),
      salt: salt,
      params: params,
      outputLength: keyLength,
    );
  }

  /// The key that wraps the user key. Never leaves the device.
  static Uint8List deriveEncKey(Uint8List masterKey) =>
      hkdfExpand(prk: masterKey, info: _encInfo, length: keyLength);

  /// The value sent to the server in the password field: base64url, unpadded,
  /// 43 characters for 32 bytes.
  ///
  /// The encoding is part of the contract, not a formatting choice. The server
  /// validates exactly this shape before accepting a registration, which is
  /// what makes it impossible for a client bug to submit the real password to
  /// an endpoint that would happily hash it.
  static String deriveAuthKeyString(Uint8List masterKey) {
    final authKey = hkdfExpand(
      prk: masterKey,
      info: _authInfo,
      length: keyLength,
    );
    return base64UrlEncode(authKey).replaceAll('=', '');
  }

  /// A fresh user key. Generated once, at registration, and never derived from
  /// anything -- so no later password change can be forced to reproduce it.
  static Uint8List generateUserKey({Random? random}) =>
      randomBytes(keyLength, random: random);

  /// A fresh per-account KDF salt.
  static Uint8List generateSalt({Random? random}) =>
      randomBytes(saltLength, random: random);

  /// Seals [userKey] under a key derived from the password.
  static Future<Uint8List> wrapUserKey({
    required CryptoEngine engine,
    required Uint8List encKey,
    required Uint8List userKey,
    String domain = EnvelopeDomain.passwordWrap,
    Random? random,
  }) {
    if (userKey.length != keyLength) {
      throw const CryptoFormatException('User key must be 32 bytes.');
    }
    return Envelope.seal(
      engine: engine,
      key: encKey,
      plaintext: userKey,
      domain: domain,
      random: random,
    );
  }

  /// Recovers the user key. A wrong password surfaces here as a
  /// [DecryptionFailure] -- there is no separate "is this password correct"
  /// question, because unwrapping is that question.
  static Future<Uint8List> unwrapUserKey({
    required CryptoEngine engine,
    required Uint8List encKey,
    required Uint8List wrapped,
    String domain = EnvelopeDomain.passwordWrap,
  }) async {
    final userKey = await Envelope.open(
      engine: engine,
      key: encKey,
      envelope: wrapped,
      domain: domain,
    );
    if (userKey.length != keyLength) {
      throw const CryptoFormatException(
        'Unwrapped key is not 32 bytes; the wrong slot was opened.',
      );
    }
    return userKey;
  }
}
