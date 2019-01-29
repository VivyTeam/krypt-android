package com.vivy.asymmetric

import com.vivy.asymmetric.RsaOperationHelper.rsaOperation
import com.vivy.support.EncryptionBase64
import timber.log.Timber
import java.nio.charset.StandardCharsets
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException

class RsaEcbPkcs1 : AsymmetricEncryption {

    internal val base64 = EncryptionBase64

    private val rsaCipher: Cipher
        get() {
            try {
                return Cipher.getInstance("RSA/ECB/PKCS1Padding")
            } catch (e: NoSuchAlgorithmException) {
                throw IllegalStateException("Failed to get cipher algorithm: RSA/ECB/PKCS1Padding", e)
            } catch (e: NoSuchPaddingException) {
                throw IllegalStateException("Failed to get cipher algorithm: RSA/ECB/PKCS1Padding", e)
            }

        }

    override fun encryptText(
        publicKey: PublicKey,
        decryptedText: String
    ): String {
        val id = UUID.randomUUID().toString()
        val startMs = System.currentTimeMillis()
        Timber.d(
            "process=rsa_encrypt_text, id=%s, status=initialize, keyclass='%s'", id,
            publicKey.javaClass.name
        )

        val encryptedBytes = rsaOperation(
            {
                val cipher = rsaCipher
                cipher.init(Cipher.ENCRYPT_MODE, publicKey)
                cipher
            },
            decryptedText.toByteArray(StandardCharsets.UTF_8)
        )

        Timber.d(
            "process=rsa_encrypt_text, id=%s, status=ends, timeMs=%s, keyclass='%s', text='%s'",
            id, System.currentTimeMillis() - startMs, publicKey.javaClass.name, decryptedText
        )

        return base64.base64(encryptedBytes)
    }

    override fun decryptText(
        privateKey: PrivateKey,
        base64AndEncryptedContent: String
    ): String {
        val id = UUID.randomUUID().toString()
        val startMs = System.currentTimeMillis()

        val encryptedContentBytes = base64.debase64(base64AndEncryptedContent)

        val decryptedBytes = rsaOperation({
            val cipher = rsaCipher
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher
        }, encryptedContentBytes)

        Timber.d(
            "process=rsa_encrypt_text, id=%s, status=ends, timeMs=%s, keyclass='%s'",
            id, System.currentTimeMillis() - startMs, privateKey.javaClass.name
        )


        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}
