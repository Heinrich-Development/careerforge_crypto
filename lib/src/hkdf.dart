import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'ascii.dart';

/// HKDF-Expand (RFC 5869 section 2.3), on HMAC-SHA256.
///
/// Expand only, with the input used directly as the pseudorandom key. That is
/// the correct half to use here, and worth saying why: HKDF-Extract exists to
/// condense a non-uniform secret -- a Diffie-Hellman result, a passphrase --
/// into a uniform one. The input here is already the output of Argon2id, which
/// is uniformly random over 32 bytes. Extracting again would be a second HMAC
/// that adds nothing.
///
/// [info] is the label that separates one derived key from another. Two
/// different labels over one master key give two keys that reveal nothing
/// about each other, which is exactly what the encryption/authentication split
/// needs.
Uint8List hkdfExpand({
  required Uint8List prk,
  required String info,
  int length = 32,
}) {
  if (length <= 0 || length > 255 * 32) {
    throw ArgumentError.value(length, 'length', 'Outside HKDF-SHA256 range');
  }

  final hmac = Hmac(sha256, prk);
  final infoBytes = byteStringBytes(info, 'An HKDF info label');
  final out = BytesBuilder(copy: false);

  var previous = const <int>[];
  // T(n) = HMAC(PRK, T(n-1) || info || n), with the counter starting at 1.
  for (var counter = 1; out.length < length; counter++) {
    previous = hmac.convert([...previous, ...infoBytes, counter]).bytes;
    out.add(previous);
  }

  return Uint8List.sublistView(out.takeBytes(), 0, length);
}
