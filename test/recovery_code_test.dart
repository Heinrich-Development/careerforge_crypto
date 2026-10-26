import 'dart:convert';
import 'dart:math';

import 'package:careerforge_crypto/careerforge_crypto.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  group('generation', () {
    test('is 160 bits, printed as eight groups of four', () {
      final code = RecoveryCode.generate();

      expect(code.bytes, hasLength(20));
      expect(
        code.formatted,
        matches(
          RegExp(
            r'^([0-9A-HJKMNP-TV-Z]{4}-){7}'
            r'[0-9A-HJKMNP-TV-Z]{4}$',
          ),
        ),
      );
    });

    test('two codes differ', () {
      expect(
        RecoveryCode.generate().formatted,
        isNot(RecoveryCode.generate().formatted),
      );
    });

    test('a seeded source produces a reproducible code, which is what lets '
        'the rest of these tests pin values', () {
      String seeded() => RecoveryCode.generate(random: Random(7)).formatted;
      expect(seeded(), seeded());
    });
  });

  group('parsing', () {
    final code = RecoveryCode.generate(random: Random(1));

    test('round-trips its own printed form', () {
      expect(
        bytesToHex(RecoveryCode.parse(code.formatted).bytes),
        bytesToHex(code.bytes),
      );
    });

    test('ignores case, separators and surrounding whitespace', () {
      final typed = '  ${code.formatted.toLowerCase().replaceAll('-', ' ')}  ';
      expect(
        bytesToHex(RecoveryCode.parse(typed).bytes),
        bytesToHex(code.bytes),
      );
    });

    test('reads the transcription slips Crockford anticipates', () {
      // A code of digits only, so substituting letters for them is the only
      // thing under test.
      const digits = '00001111222233334444555566667777';
      final expected = RecoveryCode.parse(digits).bytes;

      expect(
        bytesToHex(
          RecoveryCode.parse('OOOOIILL222233334444555566667777').bytes,
        ),
        bytesToHex(expected),
      );
    });

    test('refuses a character outside the alphabet, U included', () {
      expect(
        () => RecoveryCode.parse('UUUU1111222233334444555566667777'),
        throwsA(isA<CryptoFormatException>()),
      );
      expect(
        () => RecoveryCode.parse('!!!!1111222233334444555566667777'),
        throwsA(isA<CryptoFormatException>()),
      );
    });

    test('refuses the wrong length', () {
      expect(
        () => RecoveryCode.parse('0000-1111-2222'),
        throwsA(isA<CryptoFormatException>()),
      );
      expect(
        () => RecoveryCode.parse('${code.formatted}-0000'),
        throwsA(isA<CryptoFormatException>()),
      );
      expect(
        () => RecoveryCode.parse(''),
        throwsA(isA<CryptoFormatException>()),
      );
    });
  });

  group('derivation', () {
    final code = RecoveryCode.generate(random: Random(2));

    test('the encKey is 32 bytes and the verifier is authKey-shaped', () {
      expect(code.encKey, hasLength(32));
      expect(code.verifier, hasLength(43));
      expect(code.verifier, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
      expect(base64Url.decode('${code.verifier}='), hasLength(32));
    });

    test('the verifier reveals nothing about the encKey', () {
      // Two HKDF labels over one input. The point of the split is that the
      // value the server holds is not the value that opens anything.
      expect(bytesToHex(code.encKey), isNot(code.verifier));
      expect(
        bytesToHex(code.encKey),
        isNot(bytesToHex(base64Url.decode('${code.verifier}='))),
      );
    });

    test('both derivations follow the code, not the object', () {
      final same = RecoveryCode.parse(code.formatted);
      final other = RecoveryCode.generate(random: Random(3));

      expect(bytesToHex(same.encKey), bytesToHex(code.encKey));
      expect(same.verifier, code.verifier);
      expect(bytesToHex(other.encKey), isNot(bytesToHex(code.encKey)));
      expect(other.verifier, isNot(code.verifier));
    });

    test('pins the cross-implementation vector', () {
      // Self-generated, like the master-key vector: a fixed code with the
      // encKey and verifier it must always produce. If either changes, every
      // enrolled recovery code stops opening its account.
      final pinned = RecoveryCode.parse(
        'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789',
      );
      expect(pinned.formatted, 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789');
      expect(
        bytesToHex(pinned.bytes),
        '52d8d73e1194e95b5f19d6f9df7c0110c8531d09',
      );
      expect(
        bytesToHex(pinned.encKey),
        '8dfdabdd150d89819e903aa6dbab243ccc6cdc7445482b8303c0429d2effbb1e',
      );
      expect(pinned.verifier, '90rNFqIQYvr2wsjuUmhvJYp7f8eaHU3_cEVo__ZtNCQ');
    });
  });

  test('toString does not leak the code', () {
    final code = RecoveryCode.generate();
    expect(code.toString(), isNot(contains(code.formatted.substring(0, 4))));
  });
}
