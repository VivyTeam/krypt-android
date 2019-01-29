package com.vivy.scrypt

import com.vivy.support.Gzip
import com.vivy.symmetric.AesCbcPkcs7

object ScryptEncryption {

    val gzip = Gzip()
    private const val CPU_COST = 16384
    private const val MEMORY_COST = 8
    private const val PARALLELIZATION_PARAM = 1
    private const val DKLENFORSKEY = 32 //Intended length of the derived key.
    private const val DKLENFORIV = 16 //Intended length of the derived key.

    val aesCbcPkcs7 = AesCbcPkcs7()

    fun encrypt(
        pin: String,
        salt: String,
        data: ByteArray
    ): ScryptData {
        val genSCryptKey = SCryptKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            salt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORSKEY
        )
        val iv = SCryptKeyGenerator.getGenSCryptKey(
            genSCryptKey,
            pin.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORIV
        )
        val encryptedData = aesCbcPkcs7.encrypt(gzip.gzip(data), genSCryptKey, iv)

        return ScryptData(pin, salt, genSCryptKey, iv, encryptedData)

    }

    fun decrypt(pin:String,salt:String,encryptedData: ByteArray):ByteArray{

        val genSCryptKey = SCryptKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            salt.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORSKEY
        )
        val iv = SCryptKeyGenerator.getGenSCryptKey(
            genSCryptKey,
            pin.toByteArray(),
            CPU_COST,
            MEMORY_COST,
            PARALLELIZATION_PARAM,
            DKLENFORIV
        )

        return gzip.gunzip(aesCbcPkcs7.decrypt(encryptedData, genSCryptKey, iv))
    }


}