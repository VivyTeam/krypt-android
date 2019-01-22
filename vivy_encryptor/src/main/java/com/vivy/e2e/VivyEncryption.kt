package com.vivy.e2e

import java.security.PrivateKey
import java.security.PublicKey

class VivyEncryption : E2EEncryption {

     private val rsaEcbOeapSha256AesGcmNoPadding: E2EEncryption = RsaEcbOeapSha256AesGcmNoPadding()
     private val rsaEcbPkcs1AesCbcPkcs7: E2EEncryption = RsaEcbPkcs1AesCbcPkcs7()

    override val version: String
        get() = rsaEcbOeapSha256AesGcmNoPadding.version

    override fun encrypt(
        publicKey: PublicKey,
        plainData: ByteArray
    ): E2EEncryption.Encrypted {
        return rsaEcbOeapSha256AesGcmNoPadding.encrypt(publicKey, plainData)
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encrypted: E2EEncryption.Encrypted
    ): ByteArray {
        val version = encrypted.version
        return if (rsaEcbOeapSha256AesGcmNoPadding.version.equals(version, ignoreCase = true)) {
            rsaEcbOeapSha256AesGcmNoPadding.decrypt(privateKey, encrypted)
        } else {
            rsaEcbPkcs1AesCbcPkcs7.decrypt(privateKey, encrypted)
        }
    }
}
