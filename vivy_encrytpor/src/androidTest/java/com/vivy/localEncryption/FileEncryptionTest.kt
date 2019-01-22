package com.vivy.localEncryption

import com.vivy.support.KeyProvider
import io.reactivex.Single
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.util.Arrays

class FileEncryptionTest {
    lateinit var fileEncryption: FileEncryption

    @Before
    fun setup() {
        fileEncryption = FileEncryption(generateRandomTestKey())
    }

    private fun generateRandomTestKey(): KeyProvider {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(1024)
        val smallKeypair = keyGen.generateKeyPair()
        return object : KeyProvider {
            override fun getPrivateKey(): Single<PrivateKey> {
                return Single.just(smallKeypair.private)
            }

            override fun getPublicKey(): Single<PublicKey> {
                return Single.just(smallKeypair.public)
            }
        }
    }

    @Test
    fun fileCorrectlyEncryptTest() {
        val random = SecureRandom()
        val bytes = ByteArray(1048576)//3 mb
        random.nextBytes(bytes)

        val encrypted = fileEncryption.encrypt(bytes).blockingGet()


        assertNotEquals(encrypted, bytes)

    }

    @Test fun fileCorrectlyDecryptedTest() {

        val random = SecureRandom()
        val bytes = ByteArray(1048576)//1mb
        random.nextBytes(bytes)

        val encrypted = fileEncryption.encrypt(bytes).blockingGet()

        val decrypted = fileEncryption.decrypt(encrypted).blockingGet()

        assertTrue(decrypted.isPresent)

        assertTrue(Arrays.equals(decrypted.get(), bytes))
    }
}