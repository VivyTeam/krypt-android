package com.vivy.e2e

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException

class VivyEncryptionTest {

    private var smallKeypair: KeyPair

    private val rsaEcbPkcs1AesCbcPkcs7 = RsaEcbPkcs1AesCbcPkcs7()
    private val rsaEcbOeapSha256AesGcmNoPadding = RsaEcbOeapSha256AesGcmNoPadding()
    private val service = VivyEncryption()

    init {
        val keyGen: KeyPairGenerator
        try {
            keyGen = KeyPairGenerator.getInstance("RSA")
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException(e)
        }

        keyGen.initialize(1024)
        smallKeypair = keyGen.generateKeyPair()
    }

    @Test
    @Throws(Exception::class)
    fun encryptDecryptText() {
        val text = "secret"
        val encrypted = service.encrypt(smallKeypair.public, text.toByteArray())
        val decrypted = service.decrypt(smallKeypair.private, encrypted)

        assertEquals(text, String(decrypted))
    }

    @Test
    @Throws(Exception::class)
    fun decryptRsaEcbPkcs1AesCbcPkcs7() {
        val text = "secret"
        val encrypted = rsaEcbPkcs1AesCbcPkcs7.encrypt(smallKeypair.public, text.toByteArray())
        val decrypted = service.decrypt(smallKeypair.private, encrypted)

        assertEquals(text, String(decrypted))
    }

    @Test
    @Throws(Exception::class)
    fun decryptRsaEcbOeapSha256AesGcmNoPadding() {
        val text = "secret"
        val encrypted = rsaEcbOeapSha256AesGcmNoPadding.encrypt(smallKeypair.public, text.toByteArray())
        val decrypted = service.decrypt(smallKeypair.private, encrypted)

        assertEquals(text, String(decrypted))
    }
}