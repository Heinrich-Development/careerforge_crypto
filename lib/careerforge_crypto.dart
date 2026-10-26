/// The CareerForge key hierarchy and content envelope.
///
/// Its own package for one reason: it is the piece meant to be read by someone
/// deciding whether to believe the privacy claim, and a package boundary is
/// what stops it quietly acquiring a dependency that could carry a key off the
/// device. The README covers the format and the threat model it serves.
library;

export 'src/crypto_engine.dart';
export 'src/exceptions.dart';
export 'src/envelope.dart' show Envelope, EnvelopeDomain, randomBytes;
export 'src/hkdf.dart' show hkdfExpand;
export 'src/kdf_params.dart';
export 'src/key_hierarchy.dart';
export 'src/pure_dart_engine.dart';
export 'src/recovery_code.dart';
