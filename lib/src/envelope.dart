import 'dart:math';
import 'dart:typed_data';

import 'crypto_engine.dart';
import 'ascii.dart';
import 'exceptions.dart';

/// The one on-disk shape for every sealed byte in the product.
///
/// ```text
///   +---------+------------------+---------------------------+
///   | 1 byte  | 12 bytes         | n bytes                   |
///   | version | nonce            | ciphertext || 16-byte tag |
///   +---------+------------------+---------------------------+
/// ```
///
/// AES-256-GCM. Three decisions worth stating, because each is load-bearing:
///
/// **The version byte comes first, and is never optional.** Rotating the user
/// key, or moving to another cipher, is a client-side migration over rows the
/// server cannot read: the only way a future client can tell what it is
/// holding is if the byte was there from the first row ever written. It costs
/// one byte and it is the difference between a migration and a rewrite.
///
/// **The nonce is random per record, not a counter.** A counter needs shared
/// state across tabs, devices and offline edits, all of which write
/// concurrently -- and a repeated nonce under one key is catastrophic for GCM,
/// not merely untidy. 96 random bits per record, with a key that seals far
/// fewer than 2^32 records, keeps collision probability negligible.
///
/// **Every seal is bound to a domain** (see [EnvelopeDomain]), passed to GCM as
/// additional authenticated data. Without it, ciphertext valid in one slot is
/// valid in every slot under the same key: a wrapped user key could be pasted
/// over a vault row, or one field's ciphertext moved to another field, and the
/// tag would still verify. The domain makes the *place* part of what is
/// authenticated. It is not stored -- the reader knows which slot it is
/// reading, and a mismatch simply fails to open.
class Envelope {
  Envelope._();

  /// The only format written today. Readers must reject anything else rather
  /// than guessing.
  static const int version1 = 0x01;

  static const int _nonceLength = 12;
  static const int _tagLength = 16;

  /// Smallest legal envelope: header plus an empty ciphertext's tag.
  static const int _minimumLength = 1 + _nonceLength + _tagLength;

  static final Random _random = Random.secure();

  /// Seals [plaintext] under [key], bound to [domain].
  static Future<Uint8List> seal({
    required CryptoEngine engine,
    required Uint8List key,
    required Uint8List plaintext,
    required String domain,
    Random? random,
  }) async {
    final nonce = randomBytes(_nonceLength, random: random);
    final sealed = await engine.aesGcmSeal(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: _aad(domain),
    );

    final out = Uint8List(1 + _nonceLength + sealed.length)
      ..[0] = version1
      ..setRange(1, 1 + _nonceLength, nonce)
      ..setRange(1 + _nonceLength, 1 + _nonceLength + sealed.length, sealed);
    return out;
  }

  /// Opens an envelope written by [seal].
  ///
  /// Throws [CryptoFormatException] if the bytes are not an envelope at all --
  /// a truncated row or an unknown version, both of which are bugs or
  /// corruption rather than authentication failures. Throws [DecryptionFailure]
  /// for anything the tag rejects.
  static Future<Uint8List> open({
    required CryptoEngine engine,
    required Uint8List key,
    required Uint8List envelope,
    required String domain,
  }) async {
    if (envelope.length < _minimumLength) {
      throw const CryptoFormatException(
        'Envelope is too short to contain a nonce and a tag.',
      );
    }
    if (envelope[0] != version1) {
      throw CryptoFormatException(
        'Unsupported envelope version 0x${envelope[0].toRadixString(16)}. '
        'This client is older than the data it is reading.',
      );
    }

    return engine.aesGcmOpen(
      key: key,
      nonce: Uint8List.sublistView(envelope, 1, 1 + _nonceLength),
      ciphertext: Uint8List.sublistView(envelope, 1 + _nonceLength),
      aad: _aad(domain),
    );
  }

  /// The version byte of a stored envelope, for a migration deciding whether it
  /// has work to do. Does not authenticate anything.
  static int versionOf(Uint8List envelope) {
    if (envelope.isEmpty) {
      throw const CryptoFormatException('Empty envelope.');
    }
    return envelope[0];
  }

  static Uint8List _aad(String domain) =>
      asciiBytes('careerforge.v1.$domain', 'An envelope domain');
}

/// The domains an envelope can be bound to.
///
/// Adding one is adding a place ciphertext can live. Renaming one makes every
/// existing row in that slot unopenable -- the string is part of the
/// authenticated data, so these are storage identifiers, not labels: the
/// value never changes once written.
abstract final class EnvelopeDomain {
  /// The user key, wrapped by the key derived from the password.
  static const String passwordWrap = 'key.wrap.password';

  /// The user key, wrapped by the key derived from a recovery code.
  static const String recoveryWrap = 'key.wrap.recovery';

  /// The user key, wrapped by a WebAuthn PRF secret. Reserved: nothing
  /// writes one yet.
  static const String passkeyWrap = 'key.wrap.passkey';

  /// The account's portable preferences, whole.
  ///
  /// A bare domain rather than one per field: there is one row per account
  /// and one column in it, so there is nothing same-domain it could be
  /// swapped with — the same reason the vault's three single-slot columns
  /// keep theirs. See [forEntity] for when that stops being true.
  static const String preferences = 'preferences.content';

  /// The vault row's contact block.
  static const String vaultBasics = 'vault.basics';

  /// The vault row's document defaults.
  static const String vaultDocumentDefaults = 'vault.documentDefaults';

  /// The vault row's references note.
  static const String vaultReferencesNote = 'vault.referencesNote';

  /// One profile photograph. Its own row and its own domain, because it is
  /// the one piece of content fetched separately from the rest.
  static const String vaultPhoto = 'vault.photo';

  // One domain per entity table. Separate rather than a single
  // `vault.entity`, because the domain is authenticated data: binding an
  // experience's ciphertext to `vault.experience` means a row lifted out of
  // the experience table and dropped into the projects table stops
  // decrypting, instead of quietly rendering in the wrong section. That is
  // the whole reason a domain exists rather than a nonce alone.
  //
  // Entity rows are sealed under [forEntity] of their table's domain, never
  // the bare constant: a table has many rows under one key, so the table
  // name alone still leaves same-table rows interchangeable.

  /// [domain] bound to the one row [entityId] names — what every entity
  /// table's content is sealed under.
  ///
  /// The bare table domain stops ciphertext moving *between* tables, but a
  /// user's rows within one table share a key and would still verify if a
  /// server swapped their content columns: Job A's bullets under Job B's
  /// dates, silently. Folding the row's id into the authenticated data
  /// closes that — a moved content column simply stops opening.
  ///
  /// Two boundaries, on purpose:
  ///
  /// - **The id is bound; the row's plaintext columns are not.** `sortOrder`
  ///   (and a skill's category) are mutable by design — a reorder is meant
  ///   to cost two integers, not a re-seal — so they stay outside the AAD.
  ///   Identity is the immutable part, so identity is what gets sealed in.
  /// - **Single-slot columns keep their bare domain.** The vault row's
  ///   basics, defaults and note have nothing same-domain to be swapped
  ///   with; only tables with many rows per user need this.
  ///
  /// Like the constants above, the produced string is a storage identifier:
  /// an entity's id can never change once sealed under it, and the `:`
  /// separator is part of the format.
  static String forEntity(String domain, String entityId) =>
      '$domain:$entityId';

  /// One experience, bullets included.
  static const String vaultExperience = 'vault.experience';

  /// One project, bullets included.
  static const String vaultProject = 'vault.project';

  /// One education entry, bullets included.
  static const String vaultEducation = 'vault.education';

  /// One publication.
  static const String vaultPublication = 'vault.publication';

  /// One skill category's name.
  static const String vaultSkillCategory = 'vault.skillCategory';

  /// One skill: its label and the bullet ids it links to.
  static const String vaultSkill = 'vault.skill';

  /// One hobby or interest.
  static const String vaultHobby = 'vault.hobby';

  /// One language and the level claimed for it.
  static const String vaultLanguage = 'vault.language';

  /// One saved draft: its name, every selection into the vault, every
  /// override, and the pasted job ad.
  ///
  /// Sealed under [forEntity] of this domain like an entity row, and for the
  /// same reason — an account has many drafts under one key, so the bare
  /// domain alone would leave two of them interchangeable.
  static const String draft = 'draft';

  /// One application on the board: the company and role, the pasted ad, the
  /// contacts, the notes, the timeline, the CV that was sent — and which
  /// stage it sits in and where in that stage.
  ///
  /// Stage membership is sealed rather than a plaintext foreign key on
  /// purpose: the server never needs to query a column it would then be able
  /// to read a funnel from.
  ///
  /// Sealed under [forEntity] like a draft, and for the same reason.
  static const String application = 'application';

  /// One stage of one pipeline: its name, its kind, where it sits in the
  /// pipeline, and which space owns it. Sealed under [forEntity]; an account
  /// has many.
  static const String applicationStage = 'application.stage';

  /// One space on the board — a separate pipeline for a separate search: its
  /// name, its colour, its place among the others, whether it is archived,
  /// and the defaults the CVs and letters made from its cards start from.
  ///
  /// Only stages point at a space, and from inside their own ciphertext, so
  /// the server never learns which search a stage or a card belongs to.
  /// Sealed under [forEntity] like a stage, and for the same reason.
  static const String applicationSpace = 'application.space';

  /// One cover letter: its name, its body, the recipient block, the reason
  /// the person gave for applying, and the tone and length the last
  /// generation used.
  ///
  /// What it is *attached to* — an application, a CV, or nothing — is a pair
  /// of plaintext columns rather than sealed content, unlike the board's
  /// stage membership above. A link between two rows the server cannot open
  /// says only that they are related; a stage column would let it read a
  /// funnel.
  ///
  /// Sealed under [forEntity] like a draft, and for the same reason.
  static const String letter = 'letter';
}

/// [count] cryptographically random bytes.
///
/// [random] exists so tests can pin a nonce and compare against a fixed vector.
/// Production always takes the default, which is [Random.secure].
Uint8List randomBytes(int count, {Random? random}) {
  final source = random ?? Envelope._random;
  final out = Uint8List(count);
  for (var i = 0; i < count; i++) {
    out[i] = source.nextInt(256);
  }
  return out;
}
