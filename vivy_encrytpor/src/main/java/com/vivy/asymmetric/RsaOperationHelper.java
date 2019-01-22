package com.vivy.asymmetric;

import android.os.Build;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.Callable;
import javax.annotation.Nullable;
import javax.crypto.Cipher;

public class RsaOperationHelper {

  /**
   * Usually this method would be able to handle the cipher block size on its own. Because of a bug
   * in Android 6.0 specified in the method isAndroid6KeyBlockSizeBug,
   * this parameter can be used to make sure an appropriate block size will be used in this method.
   */
  static byte[] rsaOperation(Callable<Cipher> cipherProvider, byte[] inputBytes) {
    // if the cipher is initialized with android key, blocksize is 0, so we need to make a guess
    // so far, this 0 is only happening if it's initialized with android key for decryption
    // so we just guess use the output decryption blocksize
    int cipherBlockSize = 0;
    Cipher cipher = null;

    try {
      cipher = cipherProvider.call();
      cipherBlockSize = cipher.getBlockSize();
      if (cipherBlockSize <= 0) {
        cipherBlockSize = cipher.getOutputSize(0);
      }
      return performCipher(inputBytes, cipherBlockSize, cipher);
    } catch (Exception e) {
      if (isAndroid6KeyBlockSizeBug(cipher)) {
        try {
          cipher = cipherProvider.call();
          // uses in this case the reduced block size of the Android 6.0 bug; reduced by the overhead of 11 that gets produced by the selected padding
          return performCipher(inputBytes, 501, cipher);
        } catch (Exception e2) {
          throw new IllegalStateException("Failed to encrypt/decrypt using rsa", e2);
        }
      } else {
        throw new IllegalStateException("RSA operation failed!", e);
      }
    }
  }

  static byte[] performCipher(byte[] inputBytes, int cipherBlockSize, Cipher cipher) {
    byte[] buffer = new byte[cipherBlockSize];
    ByteArrayInputStream inStream = new ByteArrayInputStream(inputBytes);
    ByteArrayOutputStream outStream = new ByteArrayOutputStream();
    try {
      for (int r = inStream.read(buffer); r != -1; r = inStream.read(buffer)) {
        byte[] encryptedBuffer = cipher.doFinal(buffer, 0, r);
        outStream.write(encryptedBuffer);
      }
    } catch (Exception e) {
      throw new IllegalStateException("Unable to perform cipher", e);
    }
    return outStream.toByteArray();
  }

  /**
   * In Android 6.0 Marshmallow the value for the block size of the cipher results into 512 or 0.
   * 512 is too big to handle the encryption. Therefore this method checks whether the failing
   * encryption is based on that bug.
   * If the block size is 0 it gets set to 512 internally in the encryption method. Therefore it is
   * included in the check.
   *
   * @param cipher cipher containing block size to be checked
   * @return whether it is the Android 6.0 bug or not
   */
  private static boolean isAndroid6KeyBlockSizeBug(@Nullable Cipher cipher) {
    return Build.VERSION.SDK_INT == Build.VERSION_CODES.M && ( cipher != null && ( cipher.getBlockSize() == 512 || cipher.getBlockSize() == 0 ) );
  }
}
