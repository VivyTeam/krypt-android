package com.vivy.asymmetric

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator

class RsaEcbOeapSha256Test {

    private val service = RsaEcbOeapSha256()

    @Test
    @Throws(Exception::class)
    fun encryptDecryptText() {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(1024)
        val smallKeypair = keyGen.generateKeyPair()

        val text = "secret"
        val encryptedText = service.encryptText(smallKeypair.public, text)
        val decryptedText = service.decryptText(smallKeypair.private, encryptedText)

        assertEquals(text, decryptedText)
    }
}