package com.vivy.medicalSticker.v2

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.medicalSticker.MedStickerEncryption
import com.vivy.medicalSticker.MedStickerKeyGenerator
import com.vivy.medicalSticker.v2.model.EmergencyStickerCipherAttr
import com.vivy.medicalSticker.v2.model.EncryptedEmergencySticker
import com.vivy.symmetric.AesGcmNoPadding
import java.security.SecureRandom

object EmergencyStickerEncryption {
    var debug: Boolean = false
    internal const val CPU_COST = 16384
    internal const val MEMORY_COST = 10
    internal const val PARALLELIZATION_PARAM = 1
    internal const val PIN_KEY_LENGTH = 256 //Intended length of the pin key.
    internal const val PIN_FINGER_PRINT_LENGTH = 512 //Intended length of the pin finger print.
    internal const val AES_IV_LENGTH = 128 //Intended length of aes key.

    private val gcmNoPadding = AesGcmNoPadding()

    /**
     * pin: From QR Code
     * firstSalt: Some fixed constant
     */

    fun getFingerprintSecret(
        pin: String,
        firstSalt: String
    ):ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            firstSalt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            PIN_KEY_LENGTH
        )
    }

    fun encrypt(
        pin: String,
        backEndSecret: String,
        secondSalt:String,
        data: ByteArray
    ): EncryptedEmergencySticker {
        val pinFingerprint = getPinFingerprint(pin, backEndSecret, secondSalt)
        val keyPairs = getKeyAndFingerprintFilePair(pinFingerprint)
        val iv = getRandomIv()

        try {
            val encryptedData = gcmNoPadding.encrypt(data, keyPairs.key, iv)
            return EncryptedEmergencySticker(encryptedData, keyPairs.fingerprintFile, EmergencyStickerCipherAttr(keyPairs.key, iv))
        }catch (e: Exception) {
            throw EncryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    /**
     * pin: From QR Code
     * pinSalt: Generated from Backend
     * pinSecret: Generated from Backend
     */
    private fun getPinFingerprint(pin: String, backEndSecret: String, secondSalt:String): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            (pin + backEndSecret).toByteArray(),
            secondSalt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            PIN_FINGER_PRINT_LENGTH
        )
    }

    private fun getKeyAndFingerprintFilePair(pinFingerprint: ByteArray): EmergencyStickerKeyPairs {
        val dividedFingerprint = pinFingerprint.toList().chunked(2)
        val key = dividedFingerprint[0].toByteArray()
        val fingerprintFile = dividedFingerprint[1].toByteArray()
        return EmergencyStickerKeyPairs(key, fingerprintFile)
    }

    private fun getRandomIv(): ByteArray {
        val bytes = ByteArray(AES_IV_LENGTH)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    fun decrypt(
        encryptedData: ByteArray,
        attr: EmergencyStickerCipherAttr
    ): ByteArray {
        try {
            return gcmNoPadding.decrypt(encryptedData, attr.key, attr.iv)
        } catch (e: Exception) {
            throw DecryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    data class EmergencyStickerKeyPairs(
        val key: ByteArray, // first half of finger print
        val fingerprintFile: ByteArray // second half of finger print
    )
}