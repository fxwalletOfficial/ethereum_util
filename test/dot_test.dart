import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:convert/convert.dart' show hex;

import 'package:ethereum_util/ethereum_util.dart';

void main() {
  const String TEST_MNEMONIC =
      'caution juice atom organ advance problem want pledge someone senior holiday very';

  /// ********************************************start*******************************************
  test('dot demo', () async {
    /// address generate, default prefix 0;
    final address = await Dot.mnemonicToAddress(TEST_MNEMONIC);
    expect(address, '1472PzLbTz89JPnHfo7WxuyPwyfYxJeQWNVjC438BLJGaznU');

    /// sign message
    final privateKey = hex.decode(
        'c0a2711a7a22f3cd788377a21687b383deb61fec2316c4369acecd1d6ca0f958');
    final publicKey = hex.decode(
        '894cdf92dc41ee11f3bbd60ed91509af28277a922ce36cedb9ecead306703c01');

    /// without 0x9c
    final message =
        '0500009ea0acfa4a4b5a19c512df75afc9b1d5a9e1a1acf872018f956c8526e11efa00028907003500140041420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3bd44f5a7b303737a78347cc54297aec16442b91f9db5f074027d152ac4d80c68';
    final signedMessage = ED25519.sign(Uint8List.fromList(privateKey), message);
    assert(
        ED25519.verify(Uint8List.fromList(publicKey), signedMessage, message));
  });

  /// ********************************************end*******************************************

  group('test dot address generate by', () {
    test('mnemonic 12', () async {
      final Uint8List privateKey =
          await Dot.mnemonicToPrivateKey(TEST_MNEMONIC);
      expect(hex.encode(privateKey),
          'c0a2711a7a22f3cd788377a21687b383deb61fec2316c4369acecd1d6ca0f958');
      final publicKey = Uint8List.fromList(hex.decode(
          '894cdf92dc41ee11f3bbd60ed91509af28277a922ce36cedb9ecead306703c01'));
      String address = Dot.publicKeyToAddress(publicKey, prefix: 42);
      expect(address, '5FAjFf5XcCrfrrmmiA4Wpm9F6MfuG16GRsmF2m3mdFGkQWjU');
      address = Dot.publicKeyToAddress(publicKey, prefix: 0); // 默认地址
      expect(address, '1472PzLbTz89JPnHfo7WxuyPwyfYxJeQWNVjC438BLJGaznU');
      address = Dot.publicKeyToAddress(publicKey, prefix: 2);
      expect(address, 'FgLuyRQEZsbcWbDUrsZiiWFEwx94fuStFbzRRKj73VF9kPL');
      address = await Dot.mnemonicToAddress(TEST_MNEMONIC);
      expect(address, '1472PzLbTz89JPnHfo7WxuyPwyfYxJeQWNVjC438BLJGaznU');
    });
  });

  group('test signature transition', () {
    const mnemonic =
        'caution juice atom organ advance problem want pledge someone senior holiday very';
    late final privateKey;
    late final publicKey;

    late final signedRawMessage;
    late final signedMessage;
    late final signedMessageBytes;

    final rawMessage =
        '0x9c0500009ea0acfa4a4b5a19c512df75afc9b1d5a9e1a1acf872018f956c8526e11efa00028907003500140041420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3bd44f5a7b303737a78347cc54297aec16442b91f9db5f074027d152ac4d80c68';
    final unsignedMessage =
        '0500009ea0acfa4a4b5a19c512df75afc9b1d5a9e1a1acf872018f956c8526e11efa00028907003500140041420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3bd44f5a7b303737a78347cc54297aec16442b91f9db5f074027d152ac4d80c68';
    final unsignedMessageBytes =
        Uint8List.fromList(hex.decode(unsignedMessage));
    test('process message', () {
      final messageBytes = processMessage(rawMessage);
      expect(messageBytes, unsignedMessageBytes);
    });
    test('by private key', () async {
      privateKey = await Dot.mnemonicToPrivateKey(mnemonic);
      publicKey = Dot.privateKeyToPublicKey(privateKey);
      signedRawMessage = Dot.sign(rawMessage, privateKey);
      signedMessage = Dot.sign(unsignedMessage, privateKey);
      signedMessageBytes = Dot.sign(unsignedMessageBytes, privateKey);
      var result = Dot.verify(publicKey, signedRawMessage, unsignedMessage);
      assert(result);
      result = Dot.verify(publicKey, signedMessage, unsignedMessage);
      assert(result);
      result = Dot.verify(publicKey, signedMessageBytes, unsignedMessage);
      assert(result);
    });
  });
}
