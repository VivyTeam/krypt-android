package com.vivy.medicalSticker.charlie

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.medicalSticker.MedStickerCipherAttr
import com.vivy.medicalSticker.MedStickerCipherAttr.Companion.CHARLIE
import com.vivy.medicalSticker.MedStickerEncryption
import com.vivy.medicalSticker.MedStickerKeyGenerator
import com.vivy.medicalSticker.charlie.model.EncryptedEmergencySticker
import com.vivy.symmetric.AesGcmNoPadding

object EmergencyStickerEncryption {
    var debug: Boolean = false
    internal const val CHARLIE_STATIC_SALT = "5f1288159017d636c13c1c1b2835b8a871780bc2"
    internal const val CPU_COST = 16384
    internal const val MEMORY_COST = 10
    internal const val PARALLELIZATION_PARAM = 1
    internal const val HASH_LENGTH = 64
    const val AES_IV_LENGTH = 16 //Intended length of aes key.

    private val gcmNoPadding = AesGcmNoPadding()

    fun encrypt(
            data: ByteArray,
            key: ByteArray,
            iv: ByteArray
    ): ByteArray {
        try {
            return gcmNoPadding.encrypt(data, key, iv)
        } catch (e: Exception) {
            throw EncryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    fun encrypt(
            pin: String,
            secret: String,
            salt: String,
            iv: ByteArray,
            data: ByteArray
    ): EncryptedEmergencySticker {

        val keyPairs = getKeyAndFingerprintFile(pin, secret, salt)
        val encryptedData = encrypt(data, keyPairs.key, iv)
        val attr = MedStickerCipherAttr(keyPairs.key, iv, CHARLIE)

        return EncryptedEmergencySticker(encryptedData, keyPairs.fingerprintFile, attr)
    }

    /**
     * pin: From QR Code
     * salt: Generated from Backend
     * secret: Generated from Backend
     */

    internal fun getKeyAndFingerprintFile(
            pin: String,
            secret: String,
            salt: String
    ): EmergencyStickerKeyPairs {
        val hash = getHash(pin + secret, salt)
        val key = hash.dropLast(HASH_LENGTH / 2).toByteArray()
        val fingerprintFile = hash.drop(HASH_LENGTH / 2).toByteArray().asFingerprint()
        return EmergencyStickerKeyPairs(key, fingerprintFile)
    }

    fun getFingerprintSecret(pin: String): String {
        return getHash(pin, CHARLIE_STATIC_SALT).asFingerprint()
    }

    private fun getHash(
            pin: String,
            salt: String
    ): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
                pin.toByteArray(),
                salt.toByteArray(),
                CPU_COST,
                MEMORY_COST,
                PARALLELIZATION_PARAM,
                HASH_LENGTH
        )
    }

    fun decrypt(
            encryptedData: ByteArray,
            key: ByteArray,
            iv: ByteArray
    ): ByteArray {
        try {
            return gcmNoPadding.decrypt(encryptedData, key, iv)
        } catch (e: Exception) {
            throw DecryptionFailed(if (debug) e else null)
        }
    }

    fun decrypt(
            pin: String,
            secret: String,
            salt: String,
            iv: ByteArray,
            data: ByteArray
    ): ByteArray {

        val keyPairs = getKeyAndFingerprintFile(pin, secret, salt)

        return decrypt(data, keyPairs.key, iv)
    }


    data class EmergencyStickerKeyPairs(
            val key: ByteArray, // first half of fingerprint
            val fingerprintFile: String // second half of fingerprint
    )

    infix fun setDebugTo(debug: Boolean) {
        this.debug = debug
    }

    private fun ByteArray.asFingerprint(): String {
        return "$CHARLIE:" + this.joinToString("") {
            java.lang.String.format("%02x", it)
        }
    }
}