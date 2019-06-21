package com.vivy.medicalSticker.v2

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.medicalSticker.MedStickerCipherAttr
import com.vivy.medicalSticker.MedStickerCipherAttr.Companion.CHARLIE
import com.vivy.medicalSticker.MedStickerEncryption
import com.vivy.medicalSticker.MedStickerKeyGenerator
import com.vivy.medicalSticker.v2.model.EncryptedEmergencySticker
import com.vivy.support.SecureRandomGenerator
import com.vivy.symmetric.AesGcmNoPadding

object EmergencyStickerEncryption {
    var debug: Boolean = false
    internal const val CPU_COST = 16384
    internal const val MEMORY_COST = 10
    internal const val PARALLELIZATION_PARAM = 1
    internal const val HASH_LENGTH = 64
    private const val AES_IV_LENGTH = 16 //Intended length of aes key.

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

        val keyPairs = getPinFingerprint(pin, backEndSecret, secondSalt)
        val encryptedData = encrypt(data, keyPairs.key, iv)
        val attr = MedStickerCipherAttr(pin.toByteArray(), iv, CHARLIE)

        return EncryptedEmergencySticker(encryptedData, keyPairs.fingerprintFile, attr)
    }

    fun getRandomAesIv(): ByteArray {
        return SecureRandomGenerator().bytes(AES_IV_LENGTH)
    }

    /**
     * pin: From QR Code
     * pinSalt: Generated from Backend
     * pinSecret: Generated from Backend
     */

    internal fun getPinFingerprint(
        secret: String,
        backEndSecret: String,
        secondSalt:String
    ): EmergencyStickerKeyPairs{
        val hash = getHash(secret + backEndSecret, secondSalt)
        return EmergencyStickerKeyPairs(hash.copyOfRange(0, HASH_LENGTH / 2), hash.copyOfRange(HASH_LENGTH / 2, HASH_LENGTH))
    }


    fun getFingerprintSecret(secret: String, salt: String): ByteArray{
        return getHash(secret, salt).copyOfRange(0, HASH_LENGTH / 2)
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
        attr: MedStickerCipherAttr
    ): ByteArray {
        try {
            return gcmNoPadding.decrypt(encryptedData, attr.key, attr.iv)
        } catch (e: Exception) {
            throw DecryptionFailed(if (debug) e else null)
        }
    }

    fun decrypt(
        pin: String,
        backEndSecret: String,
        secondSalt:String,
        iv:ByteArray,
        data: ByteArray,
        version: String
    ): ByteArray {

        val keyPairs = getPinFingerprint(pin, backEndSecret, secondSalt)

        return decrypt(data, MedStickerCipherAttr(keyPairs.key, iv, version))
    }

    data class EmergencyStickerKeyPairs(
        val key: ByteArray, // first half of finger print
        val fingerprintFile: ByteArray // second half of finger print
    )

    infix fun setDebugTo(debug: Boolean) {
        this.debug = debug
    }
}