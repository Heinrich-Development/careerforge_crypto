import 'dart:convert';
import 'dart:io';

import 'package:careerforge_crypto/careerforge_crypto.dart';

Future<void> main() async {
  const engine = PureDartCryptoEngine();

  // Registration: a fresh salt, the expensive derivation, and the two halves.
  final salt = KeyHierarchy.generateSalt();
  final masterKey = await KeyHierarchy.deriveMasterKey(
    engine: engine,
    password: 'correct horse battery staple',
    salt: salt,
    params: KdfParams.defaults,
  );
  final encKey = KeyHierarchy.deriveEncKey(masterKey);
  stdout.writeln('authKey: ${KeyHierarchy.deriveAuthKeyString(masterKey)}');

  // The key content is sealed under, and the only copy of it the server keeps.
  final userKey = KeyHierarchy.generateUserKey();
  final wrapped = await KeyHierarchy.wrapUserKey(
    engine: engine,
    encKey: encKey,
    userKey: userKey,
  );
  stdout.writeln('wrapped userKey: ${wrapped.length} bytes');

  final sealed = await Envelope.seal(
    engine: engine,
    key: userKey,
    plaintext: utf8.encode('Senior Engineer, 2019-2024'),
    domain: EnvelopeDomain.vaultBasics,
  );
  final opened = await Envelope.open(
    engine: engine,
    key: userKey,
    envelope: sealed,
    domain: EnvelopeDomain.vaultBasics,
  );
  stdout.writeln('opened: ${utf8.decode(opened)}');

  // The same bytes, read as if they belonged in another slot, do not open.
  try {
    await Envelope.open(
      engine: engine,
      key: userKey,
      envelope: sealed,
      domain: EnvelopeDomain.vaultDocumentDefaults,
    );
    throw StateError('a seal opened under a domain it was not bound to');
  } on DecryptionFailure catch (failure) {
    stdout.writeln('under another domain: $failure');
  }
}
