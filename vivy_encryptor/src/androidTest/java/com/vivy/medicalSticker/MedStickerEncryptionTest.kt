package com.vivy.medicalSticker

import com.vivy.e2e.DecryptionFailed
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.Before
import org.junit.Test
import java.util.Arrays

class MedStickerEncryptionTest {

    val service = MedStickerEncryption

    @Before
    fun setup() {
        service setDebugTo false
    }

    @Test
    fun medicalStickerEncryptionBritneyTest() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"
        service setDebugTo true
        val scryptData = service.encrypt(code, pin, secret.toByteArray(), MedStickerKey.BRITNEY)


        assertThat(Arrays.equals(scryptData.data,secret.toByteArray()))
                .isFalse()

        val decrypted = service.decrypt(pin, code, scryptData.data, MedStickerKey.BRITNEY)

        assertThat(String(decrypted))
            .isEqualTo(secret)
    }

    @Test
    fun medicalStickerEncryptionAdamTest() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"

        val scryptData = service.encrypt(code, pin, secret.toByteArray(), MedStickerKey.ADAM)

        assertThat(Arrays.equals(scryptData.data,secret.toByteArray()))
                .isFalse()

        val decrypted = service.decrypt(pin, code, scryptData.data, MedStickerKey.ADAM)

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

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data, MedStickerKey.ADAM) }
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

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data, MedStickerKey.BRITNEY) }
            .isInstanceOf(DecryptionFailed::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }

    @Test
    fun generateKeyBritneyShouldDriveKeyFromScrypt() {
        val version = MedStickerKey.BRITNEY
        val key = service.generateKey("code", "pin", version)
        val generatedKey = MedStickerKeyGenerator.getGenSCryptKey(
            "pin".toByteArray(),
            "code".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST_BRITNEY,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORSKEY
        )
        assertThat(Arrays.equals(key, generatedKey))
            .withFailMessage("generated key should be exactly as scrypt key")
            .isTrue()

    }

    @Test
    fun generateKeyAdamShouldDriveKeyFromScrypt() {
        val version = MedStickerKey.ADAM
        val key = service.generateKey("code", "pin", version)
        val generatedKey = MedStickerKeyGenerator.getGenSCryptKey(
            "pin".toByteArray(),
            "code".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST_ADAM,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORSKEY
        )
        assertThat(Arrays.equals(key, generatedKey))
            .withFailMessage("generated key should be exactly as scrypt key")
            .isTrue()

    }

    @Test
    fun generateBritneyIVShouldDriveKeyFromScrypt() {
        val version = MedStickerKey.BRITNEY

        val iv = service.generateIV("secretKey".toByteArray(), "pin", version)

        val generatedIv = MedStickerKeyGenerator.getGenSCryptKey(
            "secretKey".toByteArray(),
            "pin".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST_BRITNEY,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORIV
        )
        assertThat(Arrays.equals(iv, generatedIv))
            .withFailMessage("generated iv should be exactly as scrypt key generated IV")
            .isTrue()

    }

    @Test
    fun generateADAMIVShouldDriveKeyFromScrypt() {
        val version = MedStickerKey.ADAM

        val iv = service.generateIV("secretKey".toByteArray(), "pin", version)

        val generatedIv = MedStickerKeyGenerator.getGenSCryptKey(
            "secretKey".toByteArray(),
            "pin".toByteArray(),
            MedStickerEncryption.CPU_COST,
            MedStickerEncryption.MEMORY_COST_ADAM,
            MedStickerEncryption.PARALLELIZATION_PARAM,
            MedStickerEncryption.DKLENFORIV
        )
        assertThat(Arrays.equals(iv, generatedIv))
            .withFailMessage("generated iv should be exactly as scrypt key generated IV")
            .isTrue()

    }

    @Test
    fun driveKeyBritneyShouldUsePinAndCodeToDriveTheKey() {
        val version = MedStickerKey.BRITNEY

        val drived = service.deriveKey("yeeXCYff", "yzuygF6M", version)

        val key = service.generateKey("yeeXCYff", "yzuygF6M", version)

        val iv = service.generateIV(key, "yzuygF6M", version)

        assertThat(Arrays.equals(key, drived.key))
            .isTrue()
            .withFailMessage("generated key should match drived key")
        assertThat(Arrays.equals(iv, drived.iv))

            .isTrue()
            .withFailMessage("generated iv should match drived key")
    }

    @Test
    fun driveKeyAdamShouldUsePinAndCodeToDriveTheKey() {
        val version = MedStickerKey.ADAM

        val drived = service.deriveKey("yeeXCYff", "yzuygF6M", version)

        val key = service.generateKey("yeeXCYff", "yzuygF6M", version)

        val iv = service.generateIV(key, "yzuygF6M", version)

        assertThat(Arrays.equals(key, drived.key))
            .isTrue()
            .withFailMessage("generated key should match drived key")
        assertThat(Arrays.equals(iv, drived.iv))

            .isTrue()
            .withFailMessage("generated iv should match drived key")
    }

}