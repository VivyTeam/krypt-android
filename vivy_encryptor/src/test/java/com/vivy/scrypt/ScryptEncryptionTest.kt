package com.vivy.scrypt


import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Before
import org.junit.Test
import java.security.Security

class ScryptEncryptionTest {


    init {
        Security.addProvider(BouncyCastleProvider())
    }

    val service=ScryptEncryption
    @Before
    fun setup(){
        service setDebugTo false
    }

    @Test
    fun `encryption decryption test`(){
        val pin = "yzuygF6M"
        val salt = "yeeXCYff"
        val secret = "secret"
        val scryptData=service.encrypt(pin,salt,secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.encryptedData }
            .isNotEqualTo(secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.genSCryptKey }
            .isNotNull()

        assertThat(scryptData)
            .extracting { it.iv }
            .isNotNull()


        val decrypted=service.decrypt(pin,salt,scryptData.encryptedData)

        assertThat(String(decrypted))
            .isEqualTo(secret)
    }

}