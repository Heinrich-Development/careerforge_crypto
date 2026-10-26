import 'dart:typed_data';

import 'exceptions.dart';

/// [value] as one byte per character, refusing anything that is not ASCII.
///
/// **The refusal is the point.** `String.codeUnits` yields UTF-16 units and
/// `Uint8List.fromList` keeps the low 8 bits of each, so `'Ł'` (U+0141)
/// silently becomes `0x41` — the letter `A`. Every string this package turns
/// into bytes is a storage identifier folded into authenticated data or an
/// HKDF label, and both rest on distinct strings producing distinct bytes.
/// Truncation breaks exactly that: two entity ids differing only above bit 8
/// would seal under the same AAD, and their content columns would be
/// interchangeable — the thing `EnvelopeDomain.forEntity` exists to prevent.
///
/// ASCII rather than UTF-8 because these are identifiers that can never
/// change once written. An ASCII assert freezes the encoding forever; UTF-8
/// would accept a wider input today and leave a future normalisation
/// question open. Every value written to date is ASCII, so this is
/// byte-identical to what it replaced.
Uint8List asciiBytes(String value, String label) {
  final units = value.codeUnits;
  for (final unit in units) {
    if (unit > 0x7f) {
      throw CryptoFormatException('$label must be ASCII: "$value".');
    }
  }
  return Uint8List.fromList(units);
}

/// [value] as one byte per character, refusing anything above `0xff`.
///
/// The looser sibling of [asciiBytes], for HKDF's `info`. Every label this
/// package passes is an ASCII constant, so the two agree in production — but
/// `info` is a byte string in RFC 5869, and appendix A.1's vector is the
/// bytes `0xf0`-`0xf9`. Asserting ASCII there would mean the package could
/// no longer be checked against the published vector, which is a worse trade
/// than the one it would buy.
///
/// What it still refuses is the silent part: a code unit above `0xff` that
/// `Uint8List.fromList` would truncate into a different byte.
Uint8List byteStringBytes(String value, String label) {
  final units = value.codeUnits;
  for (final unit in units) {
    if (unit > 0xff) {
      throw CryptoFormatException(
        '$label must be one byte per character: "$value".',
      );
    }
  }
  return Uint8List.fromList(units);
}
