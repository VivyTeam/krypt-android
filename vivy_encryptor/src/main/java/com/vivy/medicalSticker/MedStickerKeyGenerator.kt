package com.vivy.medicalSticker

object MedStickerKeyGenerator {
    var debug: Boolean = false
    fun getGenSCryptKey(
            pin: ByteArray,
            salt: ByteArray,
            cpuCost: Int = 16384,
            memoryCost: Int = 8,
            parallelizationParam: Int = 1,
            dkLen: Int = 32
    ): ByteArray {
        try {
            return org.bouncycastle.crypto.generators.SCrypt.generate(pin, salt, cpuCost, memoryCost, parallelizationParam, dkLen)
        } catch (e: Exception) {
            throw SCryptKeyGeneratorException(if (debug) e else null)
        }
    }

    infix fun setDebugTo(debug: Boolean) {
        this.debug = debug
    }
}

class SCryptKeyGeneratorException(throwable: Throwable?) : Throwable(throwable)