import 'dart:convert';
import 'dart:typed_data';

import 'package:careerforge_crypto/careerforge_crypto.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  const engine = PureDartCryptoEngine();

  Future<Uint8List> master({
    String password = testPassword,
    Uint8List? salt,
  }) => KeyHierarchy.deriveMasterKey(
    engine: engine,
    password: password,
    salt: salt ?? testSalt,
    params: testParams,
  );

  group('derivation', () {
    test('is deterministic for the same password and salt', () async {
      expect(bytesToHex(await master()), bytesToHex(await master()));
    });

    test('pins the cross-implementation vector', () async {
      // Self-generated, like the Argon2 engine vector: it exists so the
      // browser engine can be held to the same answer. If this value ever
      // changes, every existing account is locked out.
      expect(
        bytesToHex(await master()),
        '818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085',
      );
    });

    test('separates encKey, authKey and the master key', () async {
      final masterKey = await master();
      final encKey = KeyHierarchy.deriveEncKey(masterKey);
      // The trailing '=' is the padding deriveAuthKeyString strips.
      final authKey = base64Url.decode(
        '${KeyHierarchy.deriveAuthKeyString(masterKey)}=',
      );

      expect(bytesToHex(encKey), isNot(bytesToHex(masterKey)));
      expect(bytesToHex(encKey), isNot(bytesToHex(authKey)));
      expect(encKey, hasLength(32));
    });

    test('a different password gives a different master key', () async {
      expect(
        bytesToHex(await master(password: 'something else entirely')),
        isNot(bytesToHex(await master())),
      );
    });

    test('a different salt gives a different master key', () async {
      expect(
        bytesToHex(await master(salt: Uint8List(16))),
        isNot(bytesToHex(await master())),
      );
    });
  });

  group('authKey string', () {
    test('is 43 characters of unpadded base64url', () async {
      final authKey = KeyHierarchy.deriveAuthKeyString(await master());

      // The server validates exactly this shape, which is what stops a client
      // bug from submitting the real password to an endpoint that would hash
      // it. 32 bytes is 43 base64 characters plus one padding character.
      expect(authKey, hasLength(43));
      expect(authKey, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
      // base64url, not standard base64: nothing that needs escaping in transit.
      expect(authKey, isNot(contains('=')));
      expect(authKey, isNot(contains('+')));
      expect(authKey, isNot(contains('/')));
    });

    test('never equals the password or the encryption key', () async {
      final masterKey = await master();
      final authKey = KeyHierarchy.deriveAuthKeyString(masterKey);

      expect(authKey, isNot(testPassword));
      expect(authKey, isNot(base64UrlEncode(masterKey)));
      expect(
        authKey,
        isNot(base64UrlEncode(KeyHierarchy.deriveEncKey(masterKey))),
      );
    });
  });

  group('user key', () {
    test('is 32 fresh bytes each time', () {
      final keys = List.generate(
        20,
        (_) => bytesToHex(KeyHierarchy.generateUserKey()),
      );
      expect(keys.toSet(), hasLength(20));
      expect(KeyHierarchy.generateUserKey(), hasLength(32));
    });

    test('wraps and unwraps', () async {
      final encKey = KeyHierarchy.deriveEncKey(await master());
      final userKey = testUserKey;

      final wrapped = await KeyHierarchy.wrapUserKey(
        engine: engine,
        encKey: encKey,
        userKey: userKey,
      );
      final unwrapped = await KeyHierarchy.unwrapUserKey(
        engine: engine,
        encKey: encKey,
        wrapped: wrapped,
      );

      expect(unwrapped, userKey);
      expect(
        String.fromCharCodes(wrapped),
        isNot(contains(String.fromCharCodes(userKey))),
      );
    });

    test('survives a password change as a re-wrap', () async {
      // The reason the hierarchy has a user key at all: changing a password
      // re-wraps 32 bytes and leaves every encrypted row untouched.
      final userKey = KeyHierarchy.generateUserKey();
      final oldEnc = KeyHierarchy.deriveEncKey(await master());
      final newSalt = Uint8List.fromList(List<int>.filled(16, 0x99));
      final newEnc = KeyHierarchy.deriveEncKey(
        await master(password: 'a brand new password', salt: newSalt),
      );

      final originallyWrapped = await KeyHierarchy.wrapUserKey(
        engine: engine,
        encKey: oldEnc,
        userKey: userKey,
      );
      final rewrapped = await KeyHierarchy.wrapUserKey(
        engine: engine,
        encKey: newEnc,
        userKey: await KeyHierarchy.unwrapUserKey(
          engine: engine,
          encKey: oldEnc,
          wrapped: originallyWrapped,
        ),
      );

      expect(
        await KeyHierarchy.unwrapUserKey(
          engine: engine,
          encKey: newEnc,
          wrapped: rewrapped,
        ),
        userKey,
      );
    });

    test('a wrong password fails to unwrap', () async {
      final wrapped = await KeyHierarchy.wrapUserKey(
        engine: engine,
        encKey: KeyHierarchy.deriveEncKey(await master()),
        userKey: testUserKey,
      );

      expect(
        KeyHierarchy.unwrapUserKey(
          engine: engine,
          encKey: KeyHierarchy.deriveEncKey(await master(password: 'wrong')),
          wrapped: wrapped,
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('a password-wrapped key will not open as a recovery wrap', () async {
      // Each unlock path wraps the same user key in its own slot. Without
      // domain separation, a copy taken from one slot would be accepted in
      // another.
      final encKey = KeyHierarchy.deriveEncKey(await master());
      final wrapped = await KeyHierarchy.wrapUserKey(
        engine: engine,
        encKey: encKey,
        userKey: testUserKey,
      );

      expect(
        KeyHierarchy.unwrapUserKey(
          engine: engine,
          encKey: encKey,
          wrapped: wrapped,
          domain: EnvelopeDomain.recoveryWrap,
        ),
        throwsA(isA<DecryptionFailure>()),
      );
    });

    test('refuses a user key that is not 32 bytes', () async {
      final encKey = KeyHierarchy.deriveEncKey(await master());
      expect(
        () => KeyHierarchy.wrapUserKey(
          engine: engine,
          encKey: encKey,
          userKey: Uint8List(16),
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });
  });

  group('parameters arriving from the server', () {
    test('are rejected below the OWASP floor', () {
      expect(
        KeyHierarchy.deriveMasterKey(
          engine: engine,
          password: testPassword,
          salt: testSalt,
          params: const KdfParams(
            memoryKiB: 8,
            iterations: 1,
            parallelism: 1,
          ),
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });

    test('accept the shipped defaults and the test floor', () {
      expect(KdfParams.defaults.meetsMinimum, isTrue);
      expect(testParams.meetsMinimum, isTrue);
    });

    test('reject a short salt', () {
      expect(
        KeyHierarchy.deriveMasterKey(
          engine: engine,
          password: testPassword,
          salt: Uint8List(4),
          params: testParams,
        ),
        throwsA(isA<CryptoFormatException>()),
      );
    });
  });
}
