package com.vivy.symmetric

import com.vivy.support.SecureRandomGenerator
import org.junit.Assert.assertEquals
import org.junit.Test

class AesGcmNoPaddingTest {

    private val random = SecureRandomGenerator()
    private val service = AesGcmNoPadding()

    @Test
    fun encryptDecrypt() {
        val data = "data".toByteArray()

        val key = random.bytes(32)
        val iv = random.bytes(16)

        val encrypted = service.encrypt(data, key, iv)
        val decrypted = service.decrypt(encrypted, key, iv)

        assertEquals("data", String(decrypted))
    }
}