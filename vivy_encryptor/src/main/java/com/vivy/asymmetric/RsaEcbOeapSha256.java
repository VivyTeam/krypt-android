package com.vivy.asymmetric;

import com.vivy.support.EncryptionBase64;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import static com.vivy.asymmetric.RsaOperationHelper.rsaOperation;

public class RsaEcbOeapSha256 implements AsymmetricEncryption {

  final EncryptionBase64 base64 = EncryptionBase64.INSTANCE;

  public String encryptText(PublicKey publicKey, String decryptedText) {
    byte[] encryptedBytes = rsaOperation(
        () -> {
          Cipher cipher = getRSACipher();
          cipher.init(Cipher.ENCRYPT_MODE, publicKey, getOaepParameterSpec());
          return cipher;
        },
        decryptedText.getBytes(StandardCharsets.UTF_8)
    );
    return base64.base64(encryptedBytes);
  }

  public String decryptText(PrivateKey privateKey, String base64AndEncryptedContent) {
    byte[] encryptedContentBytes = base64.debase64(base64AndEncryptedContent);

    byte[] decryptedBytes = rsaOperation(() -> {
      Cipher cipher = getRSACipher();
      cipher.init(Cipher.DECRYPT_MODE, privateKey, getOaepParameterSpec());
      return cipher;
    }, encryptedContentBytes);

    return new String(decryptedBytes, StandardCharsets.UTF_8);
  }

  private OAEPParameterSpec getOaepParameterSpec() {
    return new OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        new MGF1ParameterSpec("SHA-256"),
        PSource.PSpecified.DEFAULT
    );
  }

  private Cipher getRSACipher() {
    try {
      return Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new IllegalStateException(
          "Failed to get cipher algorithm: RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", e);
    }
  }
}
