package com.vivy.e2e

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator

class RsaEcbPkcs1AesCbcPkcs7Test {

    private val service = RsaEcbPkcs1AesCbcPkcs7()

    @Test
    @Throws(Exception::class)
    fun encryptDecryptText() {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(1024)
        val smallKeypair = keyGen.generateKeyPair()

        val text = "secret"
        val encrypted = service.encrypt(smallKeypair.public, text.toByteArray())
        val decrypted = service.decrypt(smallKeypair.private, encrypted)

        assertEquals(text, String(decrypted))
    }

}