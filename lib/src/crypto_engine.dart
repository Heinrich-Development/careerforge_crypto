import 'dart:typed_data';

import 'exceptions.dart';
import 'kdf_params.dart';

/// The two primitives that have a fast platform implementation, and nothing
/// else.
///
/// Everything above this line -- the envelope format, the HKDF split, the key
/// hierarchy -- is plain Dart in this package, identical on every platform and
/// testable on the VM. What varies is only *how the arithmetic is done*:
///
///   * [PureDartCryptoEngine] (this package) runs on pointycastle. It is the
///     reference implementation and what the tests pin behaviour against, and
///     it serves the app's VM test suites and tooling and anything else that
///     runs outside a browser.
///   * In production the app registers a web engine, not in this package,
///     that calls Argon2 in WebAssembly and AES-GCM through WebCrypto, because
///     a pure-Dart Argon2id compiled to JavaScript is far too slow to unlock
///     with.
///
/// Keeping the seam this narrow is the point. A second implementation has to
/// match on primitives, which are covered by published test vectors, rather
/// than on a format it could get subtly wrong.
///
/// Async because WebCrypto is async. The pure-Dart implementation is
/// synchronous underneath and simply returns completed futures.
abstract interface class CryptoEngine {
  /// Argon2id. Returns [outputLength] bytes.
  Future<Uint8List> argon2id({
    required Uint8List password,
    required Uint8List salt,
    required KdfParams params,
    int outputLength = 32,
  });

  /// AES-256-GCM. Returns ciphertext with the 16-byte tag appended, which is
  /// the layout both WebCrypto and pointycastle already use.
  ///
  /// [key] must be 32 bytes and [nonce] 12.
  Future<Uint8List> aesGcmSeal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  });

  /// The inverse of [aesGcmSeal]. [ciphertext] includes the trailing tag.
  ///
  /// Throws [DecryptionFailure] if the tag does not verify -- which covers a
  /// wrong key, wrong [aad] and tampered bytes alike. Implementations must not
  /// return plaintext they could not authenticate, and must not distinguish
  /// the cases.
  Future<Uint8List> aesGcmOpen({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List aad,
  });
}
