package com.vivy.medicalSticker

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import com.vivy.support.Gzip
import com.vivy.symmetric.AesCbcPkcs7
import com.vivy.symmetric.AesGcmNoPadding

object MedStickerEncryption {
    var debug: Boolean = false
    val gzip = Gzip()
    internal const val CPU_COST = 16384
    internal const val MEMORY_COST_ADAM = 8
    internal const val MEMORY_COST_BRITNEY = 10
    internal const val PARALLELIZATION_PARAM = 1
    internal const val DKLENFORSKEY = 32 //Intended length of the derived key.
    internal const val DKLENFORIV = 16 //Intended length of the derived key.

    private val aesCbcPkcs7 = AesCbcPkcs7()
    private val gcmNoPadding = AesGcmNoPadding()

    private val signer = MedStickerSigner
    fun encrypt(
        code: String,
        pin: String,
        data: ByteArray
    ): EncryptedMedSticker = MedStickerEncryption.encrypt(code, pin, data, MedStickerKey.BRITNEY)

    internal fun encrypt(
        code: String,
        pin: String,
        data: ByteArray,
        version: String
    ): EncryptedMedSticker {
        val medKey = deriveKey(code, pin, version)
        try {
            val encryptedData = when (version) {
                MedStickerKey.BRITNEY -> gcmNoPadding.encrypt(gzip.gzip(data), medKey.key, medKey.iv)
                MedStickerKey.ADAM -> aesCbcPkcs7.encrypt(gzip.gzip(data), medKey.key, medKey.iv)
                else -> throw UnsupportedOperationException("unsupported version used")
            }


            return EncryptedMedSticker(encryptedData, medKey)
        } catch (e: Exception) {
            throw EncryptionFailed(if (debug) e else null)
        }
    }

    fun decrypt(
        medStickerKey: MedStickerKey,
        encryptedData: ByteArray
    ): ByteArray {
        try {
            return when (medStickerKey.version) {
                MedStickerKey.BRITNEY -> gzip.gunzip(gcmNoPadding.decrypt(encryptedData, medStickerKey.key, medStickerKey.iv))
                else -> gzip.gunzip(aesCbcPkcs7.decrypt(encryptedData, medStickerKey.key, medStickerKey.iv))
            }

        } catch (e: Exception) {
            throw DecryptionFailed(if (debug) e else null)
        }
    }

    fun deriveKey(
        code: String,
        pin: String,
        version: String
    ): MedStickerKey {

        val key = generateKey(code, pin, version)

        val iv = generateIV(key, pin, version)

        return MedStickerKey(key, iv, version)
    }

    internal fun generateIV(
        key: ByteArray,
        pin: String,
        version: String
    ): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            key,
            pin.toByteArray(),
            CPU_COST,
            getMemoryCost(version),
            PARALLELIZATION_PARAM,
            DKLENFORIV
        )
    }

    internal fun getMemoryCost(version: String): Int {
        return when (version) {
            MedStickerKey.BRITNEY -> MEMORY_COST_BRITNEY
            else -> MEMORY_COST_ADAM
        }
    }

    internal fun generateKey(
        code: String,
        pin: String,
        version: String
    ): ByteArray {
        return MedStickerKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            code.toByteArray(),
            CPU_COST,
            getMemoryCost(version),
            PARALLELIZATION_PARAM,
            DKLENFORSKEY
        )
    }

    internal fun decrypt(
        pin: String,
        code: String,
        encryptedData: ByteArray,
        version: String
    ): ByteArray {
        val medKey = deriveKey(code, pin, version)
        try {
            return MedStickerEncryption.decrypt(medKey,encryptedData)
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