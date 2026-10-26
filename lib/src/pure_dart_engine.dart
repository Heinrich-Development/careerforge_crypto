import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'crypto_engine.dart';
import 'exceptions.dart';
import 'kdf_params.dart';

/// The reference [CryptoEngine]: pure Dart, on pointycastle.
///
/// Used by this package's own tests, by the app's VM test suites and tooling,
/// and by anything else that needs the primitives outside a browser. In
/// production the app registers a WebCrypto and WebAssembly-Argon2 engine
/// behind the same interface, for speed. The vectors in `test/vectors.dart`
/// are the answers a second engine is held to; this one is pinned to them
/// here, the browser engine by whoever checks it against them.
class PureDartCryptoEngine implements CryptoEngine {
  /// Stateless; one instance serves any number of concurrent calls.
  const PureDartCryptoEngine();

  @override
  Future<Uint8List> argon2id({
    required Uint8List password,
    required Uint8List salt,
    required KdfParams params,
    int outputLength = 32,
  }) async {
    final generator = Argon2BytesGenerator()
      ..init(
        Argon2Parameters(
          Argon2Parameters.ARGON2_id,
          salt,
          version: Argon2Parameters.ARGON2_VERSION_13,
          iterations: params.iterations,
          memory: params.memoryKiB,
          lanes: params.parallelism,
          desiredKeyLength: outputLength,
        ),
      );

    final out = Uint8List(outputLength);
    generator.deriveKey(password, 0, out, 0);
    return out;
  }

  @override
  Future<Uint8List> aesGcmSeal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) async {
    final cipher = _gcm(key: key, nonce: nonce, aad: aad, forEncryption: true);
    return cipher.process(plaintext);
  }

  @override
  Future<Uint8List> aesGcmOpen({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List aad,
  }) async {
    final cipher = _gcm(key: key, nonce: nonce, aad: aad, forEncryption: false);
    try {
      return cipher.process(ciphertext);
    } on InvalidCipherTextException {
      // The tag did not verify. Collapsed into one opaque failure on purpose --
      // see DecryptionFailure.
      throw const DecryptionFailure();
    }
  }

  GCMBlockCipher _gcm({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
    required bool forEncryption,
  }) {
    if (key.length != 32) {
      throw const CryptoFormatException('AES key must be 32 bytes.');
    }
    if (nonce.length != 12) {
      throw const CryptoFormatException('GCM nonce must be 12 bytes.');
    }
    // 128 is the tag length in bits. Shortening it is a documented way to
    // weaken GCM and there is no reason to here.
    return GCMBlockCipher(AESEngine())
      ..init(forEncryption, AEADParameters(KeyParameter(key), 128, nonce, aad));
  }
}
