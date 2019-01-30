package com.vivy.scrypt


object SCryptKeyGenerator {
    var debug: Boolean = false
    fun getGenSCryptKey(
        pin: ByteArray,
        salt: ByteArray,
        cpuCost: Int = 16384,
        memoryCost: Int = 8,
        parallelizationParam: Int = 1,
        dkLen: Int = 32//Intended length of the derived key.
    ): ByteArray {
        try {
            return org.bouncycastle.crypto.generators.SCrypt.generate(pin,salt,cpuCost,memoryCost,parallelizationParam,dkLen)
        } catch (e: Exception) {
            throw SCryptKeyGeneratorException(if(debug) e else null)
        }
    }

    infix fun setDebugTo(debug: Boolean) {
        this.debug = debug
    }
}