package com.vivy.asymmetric

import com.vivy.asymmetric.RsaOperationHelper.rsaOperation
import com.vivy.support.Base64Encoder
import java.lang.Exception
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

class RsaEcbPkcs1 : AsymmetricEncryption {

    internal val base64 = Base64Encoder

    private val rsaCipher: Cipher
        get() {
            try {
                return Cipher.getInstance("RSA/ECB/PKCS1Padding")
            } catch (e: Exception) {
                throw IllegalStateException("Failed to get cipher algorithm: RSA/ECB/PKCS1Padding", e)
            }

        }

    override fun encryptText(
        publicKey: PublicKey,
        decryptedText: String
    ): String {
        val encryptedBytes = rsaOperation(
            {
                val cipher = rsaCipher
                cipher.init(Cipher.ENCRYPT_MODE, publicKey)
                cipher
            },
            decryptedText.toByteArray(StandardCharsets.UTF_8)
        )


        return base64.base64(encryptedBytes)
    }

    override fun decryptText(
        privateKey: PrivateKey,
        base64AndEncryptedContent: String
    ): String {
        val encryptedContentBytes = base64.debase64(base64AndEncryptedContent)

        val decryptedBytes = rsaOperation({
            val cipher = rsaCipher
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher
        }, encryptedContentBytes)

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}
