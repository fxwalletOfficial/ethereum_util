import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:convert/convert.dart' show hex;
import 'package:ss58/ss58.dart';
import 'package:sr25519/sr25519.dart';

import 'utils/crypto.dart';
import 'utils/bigint.dart';

final DOT_PATH = "m/44'/354'/0'/0'/0'";
const ED25519_CRYPTO = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;

class Dot {
  static Future<Uint8List> mnemonicToPrivateKey(String mnemonic) async {
    final seed = mnemonicToSeed(mnemonic);
    final result = ledgerMaster(seed);
    return Uint8List.fromList(result.sublist(0, 32));
  }

  /// get all address
  static Future<List> mnemonicToAddresses(String mnemonic) async {
    final addresses = [];
    String address0 = await mnemonicToAddress(mnemonic);
    addresses.add(address0);
    String address2 = await mnemonicToAddress(mnemonic, prefix: 2);
    addresses.add(address2);
    String address42 = await mnemonicToAddress(mnemonic, prefix: 42);
    addresses.add(address42);
    return addresses;
  }

  static Uint8List privateKeyToPublicKey(Uint8List privateKey) {
    final MiniSecretKey priv = MiniSecretKey.fromHex(hex.encode(privateKey));
    final PublicKey pub = priv.public();
    final publicBytes = pub.encode();
    return Uint8List.fromList(publicBytes);
  }

  static String publicKeyToAddress(Uint8List publicKey, {prefix = 0}) {
    return Address(prefix: prefix, pubkey: publicKey).encode();
  }

  static Future<String> mnemonicToAddress(String mnemonic, {prefix = 0}) async {
    final privateKey = await mnemonicToPrivateKey(mnemonic);
    final publicKey = ED25519.privateKeyToPublicKey(privateKey);
    return publicKeyToAddress(publicKey, prefix: prefix);
  }

  static String sign(dynamic message, Uint8List privateKey) {
    final msg = processMessage(message);
    final MiniSecretKey priv = MiniSecretKey.fromHex(hex.encode(privateKey));
    var sk = priv.expandEd25519();
    final transcript = Sr25519.newSigningContext(utf8.encode('substrate'), msg);
    final signature = sk.sign(transcript);
    return hex.encode(signature.encode());
  }

  static bool verify(
      Uint8List publicKey, String signedMessage, String message) {
    Signature signature = Signature.fromHex(signedMessage);
    final PublicKey pubKey = PublicKey.fromHex(hex.encode(publicKey));
    final result = Sr25519.verify(
        pubKey, signature, Uint8List.fromList(hex.decode(message)));
    return result.$1;
  }
}

/// derive path
Uint8List ledgerMaster(Uint8List seed) {
  final chainCode = Hmac(sha256, utf8.encode(ED25519_CRYPTO))
      .convert(Uint8List.fromList([1, ...seed]))
      .bytes;
  List<int> priv = [];
  while (priv.length == 0 || (priv[31] & 32) != 0) {
    List<int> convertBytes = priv;
    if (priv.length == 0) {
      convertBytes = seed;
    }
    priv =
        Hmac(sha512, utf8.encode(ED25519_CRYPTO)).convert(convertBytes).bytes;
  }
  priv[0] &= 248;
  priv[31] &= 127;
  priv[31] |= 64;
  var result = Uint8List.fromList([...priv, ...chainCode]);
  result = ledgerDerivePrivate(result, 44);
  result = ledgerDerivePrivate(result, 354);
  result = ledgerDerivePrivate(result, 0);
  result = ledgerDerivePrivate(result, 0);
  result = ledgerDerivePrivate(result, 0);
  return result;
}

Uint8List ledgerDerivePrivate(Uint8List xprv, int index) {
  final kl = xprv.sublist(0, 32);
  final kr = xprv.sublist(32, 64);
  final cc = xprv.sublist(64, 96);
  final offset = bnToU8a(BigInt.from(index + HARDENED_OFFSET));
  final data = Uint8List.fromList([0, ...kl, ...kr, ...offset]);
  final z = hmacShaAsU8a(cc, data, 512);
  data[0] = 0x01;

  final klBn = u8aToBn(kl);
  final z28 = u8aToBn(z.sublist(0, 28));
  final resultBn1 = klBn + (z28 * BigInt.from(8));
  final resultBytes1 = bnToU8a(resultBn1);
  final part1 = resultBytes1.sublist(0, 32);

  final krBn = u8aToBn(kr);
  final z32_64 = u8aToBn(z.sublist(32, 64));
  final resultBn2 = krBn + z32_64;
  final resultBytes2 = bnToU8a(resultBn2);
  final part2 = resultBytes2.sublist(0, 32);

  final part3 = hmacShaAsU8a(cc, data, 512).sublist(32, 64);
  return Uint8List.fromList([...part1, ...part2, ...part3]);
}

Uint8List hmacShaAsU8a(Uint8List key, Uint8List data, int bits) {
  final hmac = Hmac(sha512, key);
  final digest = hmac.convert(data);
  final bytes = digest.bytes;
  final result = Uint8List.fromList(bytes.sublist(0, bits ~/ 8));
  return result;
}

/// delete message prefix 0x9c
Uint8List processMessage(dynamic message) {
  late final Uint8List msg;
  final isString = message is String;
  final isBytes = message is Uint8List;
  if (!isString && !isBytes) throw new Exception('Unsupported message type');
  if (isString) {
    String messageNo0x = message;
    if (message.startsWith('0x')) {
      // delete 0x
      messageNo0x = message.substring('0x'.length);
    }
    msg = Uint8List.fromList(hex.decode(messageNo0x));
  } else {
    msg = message;
  }
  // delete prefix 9c
  if (msg[0] == 156) return msg.sublist(1);
  return msg;
}
