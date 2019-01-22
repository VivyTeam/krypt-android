package com.vivy.symmetric

interface SymmetricEncryption {

    fun encrypt(
        data: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray

    fun decrypt(
        encryptedData: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray
}
