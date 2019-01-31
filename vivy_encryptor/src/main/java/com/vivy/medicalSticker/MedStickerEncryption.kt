package com.vivy.medicalSticker

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.support.Gzip
import com.vivy.symmetric.AesCbcPkcs7

object MedStickerEncryption {
    var debug: Boolean = false
    val gzip = Gzip()
    internal const val CPU_COST = 16384
    internal const val MEMORY_COST = 8
    internal const val PARALLELIZATION_PARAM = 1
    internal const val DKLENFORSKEY = 32 //Intended length of the derived key.
    internal const val DKLENFORIV = 16 //Intended length of the derived key.

    private val aesCbcPkcs7 = AesCbcPkcs7()
    private val signer = MedStickerSigner
    fun encrypt(
        code: String,
        pin: String,
        data: ByteArray
    ): EncryptedMedSticker {
        val medKey = deriveKey(code, pin)
        val encryptedData = aesCbcPkcs7.encrypt(gzip.gzip(data), medKey.key, medKey.iv)

        try {
            return EncryptedMedSticker(encryptedData, MedStickerKey(medKey.key, medKey.iv))
        } catch (e: Exception) {
            throw EncryptionFailed(if (debug) e else null)
        }
    }

    fun decrypt(
        medStickerKey: MedStickerKey,
        encryptedData: ByteArray
    ): ByteArray {
        try {
            return gzip.gunzip(aesCbcPkcs7.decrypt(encryptedData, medStickerKey.key, medStickerKey.iv))
        } catch (e: Exception) {
            throw DecryptionFailed(if (debug) e else null)
        }
    }

    fun deriveKey(
        code: String,
        pin: String
    ): MedStickerKey {

        val key = generateKey(code, pin)

        val iv = generateIV(key, pin)

        return MedStickerKey(key, iv)
    }

    internal fun generateIV(
        key: ByteArray,
        pin: String
    ): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            key,
            pin.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORIV
        )
    }

    internal fun generateKey(
        code: String,
        pin: String
    ): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            code.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORSKEY
        )
    }

    internal fun decrypt(
        pin: String,
        code: String,
        encryptedData: ByteArray
    ): ByteArray {
        val medKey = deriveKey(code, pin)
        try {
            return gzip.gunzip(aesCbcPkcs7.decrypt(encryptedData, medKey.key, medKey.iv))
        } catch (e: Exception) {
            throw DecryptionFailed(if (debug) e else null)
        }
    }

    fun accessSignature(
        medStickerKey: MedStickerKey,
        salt: ByteArray
    ) = signer.accessSignature(medStickerKey, salt)

    infix fun setDebugTo(debug: Boolean) {
        this.debug = debug
    }
}