import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'envelope.dart';
import 'hkdf.dart';
import 'exceptions.dart';

/// The second way into an account: 160 random bits, shown once, that wrap the
/// same userKey the password wraps.
///
/// ```text
///   recoveryCode ...... 20 random bytes, Crockford base32, shown once
///         |
///         +-- HKDF "careerforge.recovery.enc"    --> encKey
///         |                                          wraps the userKey
///         |
///         +-- HKDF "careerforge.recovery.verify" --> verifier
///                                                    base64url, sent to the
///                                                    server
/// ```
///
/// The same split as the password hierarchy, for the same reason: what the
/// server holds proves someone knows the code without being usable to open
/// anything.
///
/// **There is no Argon2id here, and that is deliberate.** Stretching exists to
/// buy entropy a human password does not have; this value is 160 bits straight
/// from a CSPRNG, so there is nothing to guess offline and nothing a KDF would
/// add. It also has to work in the one flow where the account's KDF parameters
/// are not available — a reset is exactly the moment the client cannot log in
/// to fetch them.
///
/// **The alphabet is ASCII by construction**, which sidesteps the Unicode
/// normalisation gap the README records for passwords: a recovery code cannot
/// be typed in two byte-different ways that look the same. Crockford base32
/// also excludes `I`, `L`, `O` and `U`, and [RecoveryCode.parse] maps the
/// first three onto the digits they are mistaken for, so a code read off paper
/// survives the usual transcription slips.
///
/// The code itself never reaches the server — only the verifier does, and only
/// during a reset.
final class RecoveryCode {
  const RecoveryCode._(this.bytes);

  /// 160 bits: comfortably past brute force, and exactly 32 base32 characters
  /// with no padding, which is what makes the printed form eight clean groups
  /// of four.
  static const int byteLength = 20;

  /// Characters in the canonical printed form, before grouping.
  static const int characterLength = 32;

  static const int _groupSize = 4;

  /// Crockford base32: RFC 4648's alphabet with `I`, `L`, `O` and `U`
  /// removed. A storage identifier — changing it makes every enrolled code
  /// undecodable.
  static const String _alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  /// HKDF label for the key that wraps the user key under this code.
  static const String _encInfo = 'careerforge.recovery.enc';

  /// HKDF label for the value the server stores a hash of.
  static const String _verifyInfo = 'careerforge.recovery.verify';

  /// The decoded code. Key material: never log it, never persist it.
  final Uint8List bytes;

  /// A fresh code.
  ///
  /// [random] exists so a test can pin one. Production always takes the
  /// default, which is [Random.secure].
  factory RecoveryCode.generate({Random? random}) =>
      RecoveryCode._(randomBytes(byteLength, random: random));

  /// Reads a code a person typed or pasted.
  ///
  /// Forgiving about everything that carries no information — case, the group
  /// separators, surrounding whitespace — and forgiving about the three
  /// substitutions Crockford anticipates: `I` and `L` read as `1`, `O` as `0`.
  /// `U` is not aliased; Crockford leaves it out to keep generated codes from
  /// spelling things, so a `U` in input is a typo rather than a digit.
  ///
  /// Throws [CryptoFormatException] for anything that is not a code, which is
  /// the caller's cue to say "that is not a recovery code" rather than "that
  /// code is wrong" — the two failures are worth different words.
  factory RecoveryCode.parse(String input) {
    final buffer = StringBuffer();
    for (final unit in input.toUpperCase().codeUnits) {
      final character = String.fromCharCode(unit);
      if (character == '-' || character == ' ') continue;
      final normalized = switch (character) {
        'I' || 'L' => '1',
        'O' => '0',
        _ => character,
      };
      if (!_alphabet.contains(normalized)) {
        throw const CryptoFormatException(
          'Recovery code contains a character that is not in the alphabet.',
        );
      }
      buffer.write(normalized);
    }

    final characters = buffer.toString();
    if (characters.length != characterLength) {
      throw CryptoFormatException(
        'A recovery code is $characterLength characters; '
        'this one has ${characters.length}.',
      );
    }
    return RecoveryCode._(_decode(characters));
  }

  /// The form to show a person: eight hyphenated groups of four.
  ///
  /// The only method that should ever put a code on a screen, and it is shown
  /// once — nothing stores this string.
  String get formatted {
    final characters = _encode(bytes);
    final groups = <String>[
      for (var i = 0; i < characters.length; i += _groupSize)
        characters.substring(i, i + _groupSize),
    ];
    return groups.join('-');
  }

  /// The key that wraps the userKey under this code. Never leaves the device.
  Uint8List get encKey => hkdfExpand(prk: bytes, info: _encInfo, length: 32);

  /// The value sent to the server, in the same base64url shape as the authKey:
  /// 43 characters, unpadded, over 32 bytes.
  ///
  /// The server stores a hash of this and can do nothing else with it. Knowing
  /// it does not lead to [encKey] — they are two HKDF labels over one input,
  /// and neither output reveals the other.
  String get verifier => base64UrlEncode(
    hkdfExpand(prk: bytes, info: _verifyInfo, length: 32),
  ).replaceAll('=', '');

  /// Redacted on purpose. A code that reaches a log or a crash report is a
  /// code that has to be reissued, and `toString` is how that happens by
  /// accident. Use [formatted] to show one deliberately.
  @override
  String toString() => 'RecoveryCode(redacted)';

  static String _encode(Uint8List input) {
    final out = StringBuffer();
    var accumulator = 0;
    var bits = 0;
    for (final byte in input) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        out.write(_alphabet[(accumulator >> bits) & 0x1f]);
      }
    }
    // 20 bytes is 160 bits, an exact multiple of 5, so nothing is left over
    // and there is no padding branch to get wrong.
    return out.toString();
  }

  static Uint8List _decode(String characters) {
    final out = Uint8List(byteLength);
    var accumulator = 0;
    var bits = 0;
    var index = 0;
    for (final character in characters.split('')) {
      accumulator = (accumulator << 5) | _alphabet.indexOf(character);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out[index++] = (accumulator >> bits) & 0xff;
      }
    }
    return out;
  }
}
