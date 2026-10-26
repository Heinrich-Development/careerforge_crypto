/// The Argon2id cost parameters an account's master key was derived with.
///
/// Stored per account, plaintext, on the server. Two reasons it is a column
/// rather than a constant:
///
///   * raising the defaults later must not lock out everyone who registered
///     before the change -- an old account keeps deriving with the parameters
///     its verifier was built from until it is deliberately re-keyed;
///   * the right cost is a device question, not a security-theory one, and
///     the slowest devices have not been measured yet (see [defaults]).
class KdfParams {
  /// The cost one account derives with. Deriving refuses any that fail
  /// [meetsMinimum].
  const KdfParams({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  });

  /// What a new account gets today.
  ///
  /// Bitwarden's Argon2id defaults: m=64 MiB, t=3, p=1. An unlock with them
  /// measured about 200 ms in the browser on one fast desktop, and the KDF
  /// is essentially all of that time.
  ///
  /// `parallelism` is 1 on purpose. The browser implementation is
  /// single-threaded WebAssembly, where lanes buy nothing -- on that same
  /// desktop p=4 measured *slower* than p=1 (207 ms against 198 ms). It is a
  /// real cost parameter, so raising it later is a deliberate re-key, not a
  /// free win.
  ///
  /// **Not yet measured on a low-end phone.** Expect these numbers to move
  /// down, not up, if that measurement is bad.
  static const KdfParams defaults = KdfParams(
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 1,
  );

  /// Memory cost in kibibytes. 65536 is 64 MiB.
  final int memoryKiB;

  /// Time cost: passes over memory.
  final int iterations;

  /// Lanes. See [defaults] for why this is 1.
  final int parallelism;

  /// Rejects parameters weaker than OWASP's Argon2id floor (19 MiB, t=2).
  ///
  /// The parameters arrive from the server, which means they arrive from
  /// whoever controls the response. An attacker who could talk a client into
  /// deriving at m=8 t=1 would have turned the password into something
  /// brute-forceable, so this is checked client-side on the way in rather than
  /// trusted because we wrote the server.
  bool get meetsMinimum =>
      memoryKiB >= 19456 && iterations >= 2 && parallelism >= 1;

  @override
  String toString() =>
      'KdfParams(m=$memoryKiB KiB, t=$iterations, p=$parallelism)';

  @override
  bool operator ==(Object other) =>
      other is KdfParams &&
      other.memoryKiB == memoryKiB &&
      other.iterations == iterations &&
      other.parallelism == parallelism;

  @override
  int get hashCode => Object.hash(memoryKiB, iterations, parallelism);
}
