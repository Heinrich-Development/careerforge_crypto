import 'dart:typed_data';

import 'package:careerforge_crypto/careerforge_crypto.dart';

/// Fixed inputs and their expected outputs, shared by every implementation.
///
/// The point of this file is the second implementation. The browser engine
/// computes Argon2id in WebAssembly and AES-GCM through WebCrypto -- entirely
/// different code from the pointycastle reference -- and the only thing that
/// keeps the two able to read each other's data is agreeing on these answers.
/// Every suite in this package pins these values, and a second
/// implementation can be held to them.
///
/// Deliberately weak KDF parameters: these run on every test invocation, and
/// the cost of Argon2id at production settings is the point of Argon2id.
/// Correctness of the wiring is what is being pinned here, not cost.
const KdfParams testParams = KdfParams(
  memoryKiB: 19456,
  iterations: 2,
  parallelism: 1,
);

const String testPassword = 'correct horse battery staple';

/// 16 bytes, 0x00..0x0f.
Uint8List get testSalt => Uint8List.fromList(List<int>.generate(16, (i) => i));

/// 32 bytes, 0xf0 down to 0xd1 -- visibly not a salt, so a test that mixes the
/// two fails loudly rather than subtly.
Uint8List get testUserKey =>
    Uint8List.fromList(List<int>.generate(32, (i) => 0xf0 - i));

Uint8List hexToBytes(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
