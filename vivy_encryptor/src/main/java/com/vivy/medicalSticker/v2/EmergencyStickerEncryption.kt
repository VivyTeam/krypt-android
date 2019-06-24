package com.vivy.medicalSticker.v2

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.medicalSticker.MedStickerCipherAttr
import com.vivy.medicalSticker.MedStickerCipherAttr.Companion.CHARLIE
import com.vivy.medicalSticker.MedStickerEncryption
import com.vivy.medicalSticker.MedStickerKeyGenerator
import com.vivy.medicalSticker.common.toHexString
import com.vivy.medicalSticker.v2.model.EncryptedEmergencySticker
import com.vivy.support.SecureRandomGenerator
import com.vivy.symmetric.AesGcmNoPadding

object EmergencyStickerEncryption {
    var debug: Boolean = false
    internal const val CHARLIE_CONSTANT_SALT = "5f1288159017d636c13c1c1b2835b8a871780bc2"
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
    ):ByteArray{
        try {
            return gcmNoPadding.encrypt(data, key, iv)
        }catch (e: Exception) {
            throw EncryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    fun encrypt(
        pin: String,
        backEndSecret: String,
        secondSalt:String,
        data: ByteArray,
        iv: ByteArray
    ): EncryptedEmergencySticker {

        val keyPairs = getKeyAndFingerprintFile(pin, backEndSecret, secondSalt)
        val encryptedData = encrypt(data, keyPairs.key, iv)
        val attr = MedStickerCipherAttr(pin.toByteArray(), iv, CHARLIE)

        return EncryptedEmergencySticker(encryptedData, keyPairs.fingerprintFile, attr)
    }

    /**
     * pin: From QR Code
     * pinSalt: Generated from Backend
     * pinSecret: Generated from Backend
     */

    internal fun getKeyAndFingerprintFile(
        pin: String,
        secret: String,
        salt:String
    ): EmergencyStickerKeyPairs{
        val hash = getHash(pin + secret, salt)
        val key = hash.dropLast(HASH_LENGTH / 2).toByteArray()
        val fingerprintFile = CHARLIE + ":" + hash.drop(HASH_LENGTH / 2).toByteArray().toHexString()
        return EmergencyStickerKeyPairs(key, fingerprintFile)
    }

    fun getFingerprintSecret(secret: String): String{
        return CHARLIE + ":" + getHash(secret, CHARLIE_CONSTANT_SALT).toHexString()
    }

    private fun getHash(
        secret: String,
        salt: String
    ):ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            secret.toByteArray(),
            salt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            HASH_LENGTH
        )
    }

    internal fun decrypt(
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
        salt:String,
        iv:ByteArray,
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
}