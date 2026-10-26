import 'dart:typed_data';

import 'package:careerforge_crypto/careerforge_crypto.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  const engine = PureDartCryptoEngine();
  final key = Uint8List.fromList(List<int>.generate(32, (i) => i * 7 % 256));
  final message = Uint8List.fromList('Senior Engineer, 2019-2024'.codeUnits);

  Future<Uint8List> seal({
    Uint8List? plaintext,
    String domain = EnvelopeDomain.vaultBasics,
  }) => Envelope.seal(
    engine: engine,
    key: key,
    plaintext: plaintext ?? message,
    domain: domain,
  );

  group('layout', () {
    test('is version, nonce, then ciphertext with the tag', () async {
      final sealed = await seal();

      expect(sealed[0], Envelope.version1);
      expect(Envelope.versionOf(sealed), 0x01);
      // 1 version + 12 nonce + payload + 16 tag.
      expect(sealed.length, 1 + 12 + message.length + 16);
    });

    test('does not contain the plaintext', () async {
      final sealed = await seal();
      expect(
        String.fromCharCodes(sealed),
        isNot(contains('Senior Engineer')),
      );
    });

    test('seals an empty payload', () async {
      final sealed = await seal(plaintext: Uint8List(0));
      final opened = await Envelope.open(
        engine: engine,
        key: key,
        envelope: sealed,
        domain: EnvelopeDomain.vaultBasics,
      );
      expect(opened, isEmpty);
    });
  });

  group('nonce', () {
    test('differs on every seal of identical input', () async {
      // The one property whose failure is catastrophic rather than
      // inconvenient: a repeated nonce under one key breaks GCM outright.
      final seen = <String>{};
      for (var i = 0; i < 25; i++) {
        final sealed = await seal();
        seen.add(bytesToHex(sealed.sublist(1, 13)));
      }
      expect(seen, hasLength(25));
    });

    test('so identical plaintext produces different ciphertext', () async {
      expect(bytesToHex(await seal()), isNot(bytesToHex(await seal())));
    });
  });

  group('opening', () {
    test('round-trips', () async {
      final opened = await Envelope.open(
        engine: engine,
        key: key,
        envelope: await seal(),
        domain: EnvelopeDomain.vaultBasics,
      );
      expect(opened, message);
    });

    test('refuses a different domain under the same key', () async {
      // Without this, ciphertext from one slot could be pasted into another --
      // a wrapped user key over a vault row -- and would verify.
      expect(
        Envelope.open(
          engine: engine,
          key: key,
          envelope: await seal(domain: EnvelopeDomain.vaultBasics),
          domain: EnvelopeDomain.vaultDocumentDefaults,
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('refuses the same domain bound to a different entity id', () async {
      // Two rows of one table share a key and a table domain, so without
      // the id in the AAD a server could swap their content columns and
      // both would still verify — Job A's bullets under Job B's dates.
      final sealed = await seal(
        domain: EnvelopeDomain.forEntity(
          EnvelopeDomain.vaultExperience,
          '00000001-0000-4000-8000-000000000001',
        ),
      );
      expect(
        Envelope.open(
          engine: engine,
          key: key,
          envelope: sealed,
          domain: EnvelopeDomain.forEntity(
            EnvelopeDomain.vaultExperience,
            '00000001-0000-4000-8000-000000000002',
          ),
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('a bound domain still opens under the id it was sealed for', () async {
      final domain = EnvelopeDomain.forEntity(
        EnvelopeDomain.vaultSkill,
        '00000006-0000-4000-8000-000000000001',
      );
      final opened = await Envelope.open(
        engine: engine,
        key: key,
        envelope: await seal(domain: domain),
        domain: domain,
      );
      expect(opened, message);
    });

    test('refuses the wrong key', () async {
      expect(
        Envelope.open(
          engine: engine,
          key: Uint8List(32),
          envelope: await seal(),
          domain: EnvelopeDomain.vaultBasics,
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('refuses a flipped bit anywhere, nonce included', () async {
      for (final index in [1, 5, 13, 20]) {
        final sealed = await seal();
        sealed[index] ^= 0x01;
        expect(
          Envelope.open(
            engine: engine,
            key: key,
            envelope: sealed,
            domain: EnvelopeDomain.vaultBasics,
          ),
          throwsA(isA<DecryptionFailure>()),
          reason: 'byte $index',
        );
      }
    });

    test('reports a truncated row as malformed, not as a bad tag', () async {
      final sealed = await seal();
      expect(
        Envelope.open(
          engine: engine,
          key: key,
          envelope: Uint8List.sublistView(sealed, 0, 20),
          domain: EnvelopeDomain.vaultBasics,
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });

    test('refuses a domain outside ASCII rather than truncating it', () async {
      // 'Ł' is U+0141; keeping the low byte would make it 'A'. Two entity
      // ids that differ only there would then seal under identical
      // authenticated data, and their content columns would be
      // interchangeable — exactly what `forEntity` exists to prevent.
      expect(
        seal(
          domain: EnvelopeDomain.forEntity(
            EnvelopeDomain.vaultExperience,
            'Łukasz',
          ),
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });

    test('refuses an unknown version rather than guessing', () async {
      // What a client older than the data must do. Guessing here is how a
      // future key rotation would corrupt rows it did not understand.
      final sealed = await seal();
      sealed[0] = 0x02;
      expect(
        Envelope.open(
          engine: engine,
          key: key,
          envelope: sealed,
          domain: EnvelopeDomain.vaultBasics,
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });
  });
}
