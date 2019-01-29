package com.vivy.scrypt

import com.lambdaworks.crypto.SCrypt

object SCryptKeyGenerator {

    fun getGenSCryptKey(
        pin: ByteArray,
        salt: ByteArray,
        cpuCost: Int=16384,
        memoryCost: Int=8,
        parallelizationParam: Int=1,
        dkLen: Int=32//Intended length of the derived key.
    ): ByteArray {
        try {
            return SCrypt.scrypt(pin, salt, cpuCost, memoryCost, parallelizationParam, dkLen)
        } catch (e: Exception) {
            throw SCryptKeyGeneratorException//TODO add debug paramater
        }
    }
}