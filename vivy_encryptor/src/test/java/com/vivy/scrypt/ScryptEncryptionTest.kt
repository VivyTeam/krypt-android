package com.vivy.scrypt

import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.security.Security

class ScryptEncryptionTest {


    init {
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun `encryption decryption test`(){
        val pin = "yzuygF6M"
        val salt = "yeeXCYff"
        val secret = "secret"
        val scryptData=ScryptEncryption.encrypt(pin,salt,secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.pin }.isEqualTo(pin)
        assertThat(scryptData)
            .extracting { it.salt }.isEqualTo(salt)

        assertThat(scryptData)
            .extracting { it.encryptedData }
            .isNotEqualTo(secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.genSCryptKey }
            .isNotNull()

        assertThat(scryptData)
            .extracting { it.iv }
            .isNotNull()


        val decrypted=ScryptEncryption.decrypt(pin,salt,scryptData.encryptedData)

        assertThat(String(decrypted))
            .isEqualTo(secret)
    }
}