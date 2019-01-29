package com.vivy.asymmetric

import com.vivy.asymmetric.RsaOperationHelper.rsaOperation
import com.vivy.support.EncryptionBase64
import java.lang.Exception
import java.nio.charset.StandardCharsets
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class RsaEcbOeapSha256 : AsymmetricEncryption {

    internal val base64 = EncryptionBase64

    private val oaepParameterSpec: OAEPParameterSpec
        get() = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
        )

    private val rsaCipher: Cipher
        get() {
            try {
                return Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            } catch (e: Exception) {
                throw IllegalStateException(
                    "Failed to get cipher algorithm: RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", e
                )
            }
        }

    override fun encryptText(
        publicKey: PublicKey,
        decryptedText: String
    ): String {
        val encryptedBytes = rsaOperation(
            {
                val cipher = rsaCipher
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec)
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
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec)
            cipher
        }, encryptedContentBytes)

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}
