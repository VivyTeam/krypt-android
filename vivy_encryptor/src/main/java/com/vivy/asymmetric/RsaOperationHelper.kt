package com.vivy.asymmetric

import android.os.Build
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher

object RsaOperationHelper {

    /**
     * Usually this method would be able to handle the cipher block size on its own. Because of a bug
     * in Android 6.0 specified in the method isAndroid6KeyBlockSizeBug,
     * this parameter can be used to make sure an appropriate block size will be used in this method.
     */
    internal fun rsaOperation(
            cipherProvider: () -> Cipher,
            inputBytes: ByteArray
    ): ByteArray {
        // if the cipher is initialized with android key, blocksize is 0, so we need to make a guess
        // so far, this 0 is only happening if it's initialized with android key for decryption
        // so we just guess use the output decryption blocksize
        var cipherBlockSize: Int
        var cipher: Cipher? = null

        try {
            cipher = cipherProvider.invoke()
            cipherBlockSize = cipher.blockSize
            if (cipherBlockSize <= 0) {
                cipherBlockSize = cipher.getOutputSize(0)
            }
            return performCipher(inputBytes, cipherBlockSize, cipher)
        } catch (e: Exception) {
            return if (isAndroid6KeyBlockSizeBug(cipher)) {
                try {
                    cipher = cipherProvider.invoke()
                    // uses in this case the reduced block size of the Android 6.0 bug; reduced by the overhead of 11 that gets produced by the selected padding
                    performCipher(inputBytes, 501, cipher)
                } catch (e2: Exception) {
                    throw IllegalStateException("Failed to encrypt/decrypt using rsa", e2)
                }

            } else {
                throw IllegalStateException("RSA operation failed!", e)
            }
        }

    }

    private fun performCipher(
            inputBytes: ByteArray,
            cipherBlockSize: Int,
            cipher: Cipher
    ): ByteArray {
        val buffer = ByteArray(cipherBlockSize)
        val inStream = ByteArrayInputStream(inputBytes)
        val outStream = ByteArrayOutputStream()
        try {
            var r = inStream.read(buffer)
            while (r != -1) {
                val encryptedBuffer = cipher.doFinal(buffer, 0, r)
                outStream.write(encryptedBuffer)
                r = inStream.read(buffer)
            }
        } catch (e: Exception) {
            throw IllegalStateException("Unable to perform cipher", e)
        }

        return outStream.toByteArray()
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
    private fun isAndroid6KeyBlockSizeBug(cipher: Cipher?): Boolean {
        return Build.VERSION.SDK_INT == Build.VERSION_CODES.M && cipher != null && (cipher.blockSize == 512 || cipher.blockSize == 0)
    }
}
