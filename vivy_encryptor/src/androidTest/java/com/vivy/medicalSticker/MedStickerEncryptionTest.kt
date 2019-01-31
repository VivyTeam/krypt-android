package com.vivy.medicalSticker

import com.vivy.e2e.DecryptionFailed
import com.vivy.e2e.EncryptionFailed
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.Before
import org.junit.Test
import java.lang.IllegalStateException
import java.util.Arrays

class MedStickerEncryptionTest {

    val service = MedStickerEncryption

    @Before
    fun setup() {
        service setDebugTo false
    }

    @Test
    fun scryptTest() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"

        val scryptData = service.encrypt(code, pin, secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.data }
            .isNotEqualTo(secret.toByteArray())

        assertThat(scryptData)
            .extracting { it.key.key }
            .isNotNull()

        assertThat(scryptData)
            .extracting { it.key.iv }
            .isNotNull()

        val decrypted = service.decrypt(pin, code, scryptData.data)

        assertThat(String(decrypted))
            .isEqualTo(secret)
    }

    @Test
    fun errorsShouldBeSwallowedOnProduction() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"

        service setDebugTo false

        val scryptData = service.encrypt(code, pin, secret.toByteArray())

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data) }
            .isInstanceOf(DecryptionFailed::class.java)
            .hasNoCause()
    }

    @Test
    fun errorsShowStacktraceOnDebug() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"

        service setDebugTo true

        val scryptData = service.encrypt(code, pin, secret.toByteArray())

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data) }
            .isInstanceOf(DecryptionFailed::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }

    @Test
    fun generateKeyShouldDriveKeyFromScrypt() {
        val key = service.generateKey("code", "pin")
        val generatedKey = MedStickerKeyGenerator.getGenSCryptKey(
            "pin".toByteArray(),
            "code".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORSKEY
        )
        assertThat(Arrays.equals(key, generatedKey))
            .withFailMessage("generated key should be exactly as scrypt key")
            .isTrue()

    }

    @Test
    fun generateIVShouldDriveKeyFromScrypt() {
        val iv = service.generateIV("secretKey".toByteArray(), "pin")

        val generatedIv = MedStickerKeyGenerator.getGenSCryptKey(
            "secretKey".toByteArray(),
            "pin".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORIV
        )
        assertThat(Arrays.equals(iv, generatedIv))
            .withFailMessage("generated iv should be exactly as scrypt key generated IV")
            .isTrue()

    }

    @Test
    fun driveKeyShouldUsePinAndCodeToDriveTheKey() {
        val drived = service.deriveKey("yeeXCYff", "yzuygF6M")

        val key = service.generateKey("yeeXCYff", "yzuygF6M")

        val iv = service.generateIV(key, "yzuygF6M")

        assertThat(Arrays.equals(key, drived.key))
            .isTrue()
            .withFailMessage("generated key should match drived key")
        assertThat(Arrays.equals(iv, drived.iv))

            .isTrue()
            .withFailMessage("generated iv should match drived key")
    }

}