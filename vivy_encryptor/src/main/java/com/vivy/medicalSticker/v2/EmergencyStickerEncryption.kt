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
    internal const val FINGER_PRINT_SECRET_LENGTH = 32 //Intended length of the pin key.
    internal const val PIN_FINGER_PRINT_LENGTH = 64 //Intended length of the pin finger print.
    private const val AES_IV_LENGTH = 16 //Intended length of aes key.

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
            FINGER_PRINT_SECRET_LENGTH
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
        val iv = SecureRandomGenerator().bytes(AES_IV_LENGTH)

        try {
            val encryptedData = gcmNoPadding.encrypt(data, keyPairs.key, iv)
            return EncryptedEmergencySticker(encryptedData, keyPairs.fingerprintFile, MedStickerCipherAttr(pin.toByteArray(), iv, CHARLIE))
        }catch (e: Exception) {
            throw EncryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    /**
     * pin: From QR Code
     * pinSalt: Generated from Backend
     * pinSecret: Generated from Backend
     */
    internal fun getPinFingerprint(pin: String, backEndSecret: String, secondSalt:String): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            (pin + backEndSecret).toByteArray(),
            secondSalt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            PIN_FINGER_PRINT_LENGTH
        )
    }

    internal fun getKeyAndFingerprintFilePair(pinFingerprint: ByteArray): EmergencyStickerKeyPairs {
        val dividedFingerprint = pinFingerprint.toList().chunked(pinFingerprint.size / 2)
        val key = dividedFingerprint[0].toByteArray()
        val fingerprintFile = dividedFingerprint[1].toByteArray()
        return EmergencyStickerKeyPairs(key, fingerprintFile)
    }

    internal fun decrypt(
        encryptedData: ByteArray,
        attr: MedStickerCipherAttr
    ): ByteArray {
        try {
            return gcmNoPadding.decrypt(encryptedData, attr.key, attr.iv)
        } catch (e: Exception) {
            throw DecryptionFailed(if (MedStickerEncryption.debug) e else null)
        }
    }

    fun decrypt(pin: String,
        backEndSecret: String,
        secondSalt:String,
        iv:ByteArray,
        data: ByteArray,
        version: String
    ): ByteArray {

        val pinFingerprint = getPinFingerprint(pin, backEndSecret, secondSalt)
        val keyPairs = getKeyAndFingerprintFilePair(pinFingerprint)

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