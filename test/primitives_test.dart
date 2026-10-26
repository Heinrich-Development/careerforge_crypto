import 'dart:typed_data';

import 'package:careerforge_crypto/careerforge_crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

import 'vectors.dart';

/// Published vectors, against the reference engine. These are the tests that
/// say "this is really Argon2id and really AES-GCM" rather than "this is
/// self-consistent".
void main() {
  const engine = PureDartCryptoEngine();

  group('Argon2id', () {
    test('pointycastle computes the RFC 9106 section 5.3 vector', () {
      // Straight at the library, not through CryptoEngine, because the RFC's
      // vector uses a secret and associated data that the engine deliberately
      // does not expose -- the product has no use for either, and an interface
      // that accepted them would be an interface someone could misuse.
      //
      // What this pins is that the underlying primitive really is Argon2id at
      // version 0x13, and that the parameter mapping is what it looks like:
      // `memory` in kibibytes, `lanes` as parallelism, `iterations` as passes.
      // Getting that mapping wrong is silent -- it derives *a* key, just not
      // the one every other implementation derives.
      final generator = Argon2BytesGenerator()
        ..init(
          Argon2Parameters(
            Argon2Parameters.ARGON2_id,
            Uint8List.fromList(List<int>.filled(16, 0x02)),
            secret: Uint8List.fromList(List<int>.filled(8, 0x03)),
            additional: Uint8List.fromList(List<int>.filled(12, 0x04)),
            version: Argon2Parameters.ARGON2_VERSION_13,
            iterations: 3,
            memory: 32,
            lanes: 4,
            desiredKeyLength: 32,
          ),
        );

      final out = Uint8List(32);
      generator.deriveKey(
        Uint8List.fromList(List<int>.filled(32, 0x01)),
        0,
        out,
        0,
      );

      expect(
        bytesToHex(out),
        '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
      );
    });

    test('the engine pins the cross-implementation vector', () async {
      // The same RFC inputs minus the secret and associated data, which is the
      // shape the product actually uses. Self-generated, and labelled as such:
      // it proves nothing about Argon2id -- the test above does that -- and
      // exists so the browser's WebAssembly engine can be held to the same
      // answer as the pointycastle one. If this value ever changes, every
      // existing account is locked out.
      final derived = await engine.argon2id(
        password: Uint8List.fromList(List<int>.filled(32, 0x01)),
        salt: Uint8List.fromList(List<int>.filled(16, 0x02)),
        params: const KdfParams(memoryKiB: 32, iterations: 3, parallelism: 4),
        outputLength: 32,
      );

      expect(
        bytesToHex(derived),
        '03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e',
      );
    });

    test('a different salt gives a different key', () async {
      Future<String> derive(int saltByte) async => bytesToHex(
        await engine.argon2id(
          password: Uint8List.fromList('password'.codeUnits),
          salt: Uint8List.fromList(List<int>.filled(16, saltByte)),
          params: testParams,
        ),
      );

      expect(await derive(1), isNot(await derive(2)));
    });
  });

  group('HKDF-Expand, RFC 5869 appendix A.1', () {
    test('matches the published test vector', () {
      // Case 1's PRK, info and L=42. Extract is not exercised: the product
      // derives from an already-uniform Argon2id output, so hkdfExpand takes
      // the PRK directly. This asserts the Expand half against the RFC.
      final okm = hkdfExpand(
        prk: hexToBytes(
          '077709362c2e32df0ddc3f0dc47bba63'
          '90b6c73bb50f9c3122ec844ad7c2b3e5',
        ),
        info: String.fromCharCodes(hexToBytes('f0f1f2f3f4f5f6f7f8f9')),
        length: 42,
      );

      expect(
        bytesToHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );
    });

    test('different labels give unrelated keys', () {
      final prk = Uint8List.fromList(List<int>.filled(32, 0x42));
      expect(
        bytesToHex(hkdfExpand(prk: prk, info: 'careerforge.enc')),
        isNot(bytesToHex(hkdfExpand(prk: prk, info: 'careerforge.auth'))),
      );
    });

    test('produces the requested length across HMAC block boundaries', () {
      final prk = Uint8List.fromList(List<int>.filled(32, 0x11));
      for (final length in [1, 31, 32, 33, 64, 100]) {
        expect(
          hkdfExpand(prk: prk, info: 'x', length: length).length,
          length,
          reason: 'length $length',
        );
      }
    });
  });

  group('AES-256-GCM', () {
    // NIST CAVP gcmEncryptExtIV256, the 96-bit-IV / no-AAD case.
    final key = hexToBytes(
      'b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4',
    );
    final nonce = hexToBytes('516c33929df5a3284ff463d7');
    final plaintext = Uint8List(0);

    test('matches the published test vector', () async {
      final sealed = await engine.aesGcmSeal(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: Uint8List(0),
      );

      // Empty plaintext, so the whole output is the 16-byte tag.
      expect(bytesToHex(sealed), 'bdc1ac884d332457a1d2664f168c76f0');
    });

    test('round-trips a real payload', () async {
      final message = Uint8List.fromList('a CV bullet point'.codeUnits);
      final aad = Uint8List.fromList('careerforge.v1.vault.basics'.codeUnits);

      final sealed = await engine.aesGcmSeal(
        key: key,
        nonce: nonce,
        plaintext: message,
        aad: aad,
      );
      final opened = await engine.aesGcmOpen(
        key: key,
        nonce: nonce,
        ciphertext: sealed,
        aad: aad,
      );

      expect(opened, message);
      expect(sealed.length, message.length + 16, reason: 'tag is appended');
    });

    test('rejects a wrong key, a wrong nonce and wrong aad alike', () async {
      final sealed = await engine.aesGcmSeal(
        key: key,
        nonce: nonce,
        plaintext: Uint8List.fromList([1, 2, 3]),
        aad: Uint8List.fromList('right'.codeUnits),
      );

      Future<void> open({
        Uint8List? otherKey,
        Uint8List? otherNonce,
        String aad = 'right',
      }) => engine.aesGcmOpen(
        key: otherKey ?? key,
        nonce: otherNonce ?? nonce,
        ciphertext: sealed,
        aad: Uint8List.fromList(aad.codeUnits),
      );

      expect(
        open(otherKey: Uint8List(32)),
        throwsA(isA<DecryptionFailure>()),
      );
      expect(
        open(otherNonce: Uint8List(12)),
        throwsA(isA<DecryptionFailure>()),
      );
      expect(open(aad: 'wrong'), throwsA(isA<DecryptionFailure>()));
    });

    test('rejects a single flipped bit', () async {
      final sealed = await engine.aesGcmSeal(
        key: key,
        nonce: nonce,
        plaintext: Uint8List.fromList(List<int>.filled(64, 7)),
        aad: Uint8List(0),
      );
      sealed[10] ^= 0x01;

      expect(
        engine.aesGcmOpen(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
          aad: Uint8List(0),
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('refuses a key or nonce of the wrong size', () {
      expect(
        () => engine.aesGcmSeal(
          key: Uint8List(16),
          nonce: nonce,
          plaintext: Uint8List(0),
          aad: Uint8List(0),
        ),
        throwsA(isA<CryptoFormatException>()),
      );
      expect(
        () => engine.aesGcmSeal(
          key: key,
          nonce: Uint8List(16),
          plaintext: Uint8List(0),
          aad: Uint8List(0),
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });
  });
}
