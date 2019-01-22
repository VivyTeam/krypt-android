package com.vivy.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricEncryption {

  String encryptText(PublicKey publicKey, String decryptedText);

  String decryptText(PrivateKey privateKey, String base64AndEncryptedContent);
}
