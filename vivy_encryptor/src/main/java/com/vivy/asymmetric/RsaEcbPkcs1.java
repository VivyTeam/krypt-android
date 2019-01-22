package com.vivy.asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.vivy.support.EncryptionBase64;
import timber.log.Timber;

import static com.vivy.asymmetric.RsaOperationHelper.rsaOperation;

public class RsaEcbPkcs1 implements AsymmetricEncryption {

  final EncryptionBase64 base64 = EncryptionBase64.INSTANCE;

  public String encryptText(PublicKey publicKey, String decryptedText) {
    String id = UUID.randomUUID().toString();
    long startMs = System.currentTimeMillis();
    Timber.d("process=rsa_encrypt_text, id=%s, status=initialize, keyclass='%s'", id,
        publicKey.getClass().getName());

    byte[] encryptedBytes = rsaOperation(() -> {
          Cipher cipher = getRSACipher();
          cipher.init(Cipher.ENCRYPT_MODE, publicKey);
          return cipher;
        },
        decryptedText.getBytes(StandardCharsets.UTF_8)
    );

    Timber.d("process=rsa_encrypt_text, id=%s, status=ends, timeMs=%s, keyclass='%s', text='%s'",
        id, System.currentTimeMillis() - startMs, publicKey.getClass().getName(), decryptedText);

    return base64.base64(encryptedBytes);
  }

  public String decryptText(PrivateKey privateKey, String base64AndEncryptedContent) {
    String id = UUID.randomUUID().toString();
    long startMs = System.currentTimeMillis();


    byte[] encryptedContentBytes = base64.debase64(base64AndEncryptedContent);

    byte[] decryptedBytes = rsaOperation(() -> {
      Cipher cipher = getRSACipher();
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      return cipher;
    }, encryptedContentBytes);

    Timber.d("process=rsa_encrypt_text, id=%s, status=ends, timeMs=%s, keyclass='%s'",
             id, System.currentTimeMillis() - startMs, privateKey.getClass().getName());


    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

  private Cipher getRSACipher() {
    try {
      return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new IllegalStateException("Failed to get cipher algorithm: RSA/ECB/PKCS1Padding", e);
    }
  }
}
