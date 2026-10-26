// The two failures this package throws.
//
// Their own file because both are thrown from every other one — the
// envelope, the engine, the key hierarchy, the recovery code — and a reader
// following `throw DecryptionFailure` should not land in a file named for the
// KDF's cost parameters.

/// Thrown when key material is malformed, or when parameters that arrived from
/// the server are weaker than [KdfParams.meetsMinimum] allows.
class CryptoFormatException implements Exception {
  /// A failure described by [message].
  const CryptoFormatException(this.message);

  /// What was malformed. Never contains key material.
  final String message;

  @override
  String toString() => 'CryptoFormatException: $message';
}

/// Thrown when a sealed envelope will not open: wrong key, wrong domain, or
/// tampered bytes. Deliberately does not say which.
///
/// The distinction is real -- a wrong password and a corrupted row are
/// different problems -- but it is not one the caller can be told apart
/// safely, and every branch that reveals it is a padding-oracle in the making.
/// Callers decide what to show from *context* (an unlock attempt versus a row
/// read), not from the exception.
class DecryptionFailure implements Exception {
  /// The one failure, carrying nothing that could tell the cases apart.
  const DecryptionFailure();

  @override
  String toString() => 'DecryptionFailure: the envelope did not open.';
}
