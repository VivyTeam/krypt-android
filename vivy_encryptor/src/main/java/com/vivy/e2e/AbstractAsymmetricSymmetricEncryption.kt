package com.vivy.e2e

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.vivy.asymmetric.AsymmetricEncryption
import com.vivy.support.EncryptionBase64
import com.vivy.support.SecureRandomGenerator
import com.vivy.symmetric.SymmetricEncryption
import java.lang.reflect.Type
import java.security.PrivateKey
import java.security.PublicKey

abstract class AbstractAsymmetricSymmetricEncryption(
    val asymmetricEncryption: AsymmetricEncryption,
    val symmetricEncryption: SymmetricEncryption
) : E2EEncryption {

    private val base64 = EncryptionBase64
    private val secureRandomGenerator = SecureRandomGenerator()

    private val gson = GsonBuilder().disableHtmlEscaping().create()

    override fun encrypt(
        publicKey: PublicKey,
        plainData: ByteArray
    ): E2EEncryption.Encrypted {

        val key = secureRandomGenerator.bytes(32)
        val iv = secureRandomGenerator.bytes(16)
        try {
            val aesEncrypted = symmetricEncryption.encrypt(plainData, key, iv)

            val cipherJson = gson.toJson(
                mapOf<String, String>(
                    "base64EncodedKey" to base64.base64(key),
                    "base64EncodedIV" to base64.base64(iv)
                )
            )

            val encryptedCipherText = asymmetricEncryption.encryptText(publicKey, cipherJson)

            return E2EEncryption.Encrypted(
                aesEncrypted,
                encryptedCipherText,
                version
            )
        } catch (e: Throwable) {
            throw EncryptionFailed(if (debugMode) e else null)
        }
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encrypted: E2EEncryption.Encrypted
    ): ByteArray {
        try {
            val encryptedCipherText = encrypted.cipher
            val cipherJson = asymmetricEncryption.decryptText(privateKey, encryptedCipherText)
            val type: Type = object : TypeToken<Map<String, String>>() {}.type
            val cipherMap = gson.fromJson<Map<String, String>>(cipherJson, type)


            return symmetricEncryption.decrypt(
                encrypted.data,
                base64.debase64(cipherMap["base64EncodedKey"].toString()),
                base64.debase64(cipherMap["base64EncodedIV"].toString())
            )
        } catch (e: Throwable) {
            throw DecryptionFailed(if (debugMode) e else null)
        }

    }

    private var debugMode: Boolean = false

    fun setDebugModeTo(debug: Boolean) {
        this.debugMode = debug
    }

}
