package com.vivy.e2e

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.vivy.asymmetric.AsymmetricEncryption
import com.vivy.support.Base64Encoder
import com.vivy.support.SecureRandomGenerator
import com.vivy.symmetric.SymmetricEncryption
import java.lang.reflect.Type
import java.security.PrivateKey
import java.security.PublicKey

abstract class AbstractAsymmetricSymmetricEncryption(
    val asymmetricEncryption: AsymmetricEncryption,
    val symmetricEncryption: SymmetricEncryption
) : E2EEncryption {

    private val base64Encoder = Base64Encoder
    private val secureRandomGenerator = SecureRandomGenerator()

    private val gson = GsonBuilder().disableHtmlEscaping().create()

    override fun encrypt(
        publicKey: PublicKey,
        plainData: ByteArray
    ): E2EEncryption.Encrypted {

        val key = secureRandomGenerator.bytes(32)
        val iv = secureRandomGenerator.bytes(16)
        try {
            val aesEncryptedBytes = symmetricEncryption.encrypt(plainData, key, iv)

            val cipherKeysJson = gson.toJson(
                mapOf<String, String>(
                    "base64EncodedKey" to base64Encoder.base64(key),
                    "base64EncodedIV" to base64Encoder.base64(iv)
                )
            )

            val encryptedCipherKeys = asymmetricEncryption.encryptText(publicKey, cipherKeysJson)

            return E2EEncryption.Encrypted(
                aesEncryptedBytes,
                encryptedCipherKeys,
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
            val encryptedCipherKeys = encrypted.cipher
            val cipherKeysJson = asymmetricEncryption.decryptText(privateKey, encryptedCipherKeys)
            val type: Type = object : TypeToken<Map<String, String>>() {}.type
            val cipherKeysMap = gson.fromJson<Map<String, String>>(cipherKeysJson, type)


            return symmetricEncryption.decrypt(
                encrypted.data,
                base64Encoder.debase64(cipherKeysMap["base64EncodedKey"].toString()),
                base64Encoder.debase64(cipherKeysMap["base64EncodedIV"].toString())
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
