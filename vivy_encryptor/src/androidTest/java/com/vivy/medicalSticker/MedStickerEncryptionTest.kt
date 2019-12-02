package com.vivy.medicalSticker

import com.vivy.e2e.DecryptionFailed
import com.vivy.support.Base64Encoder
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.Before
import org.junit.Test
import java.util.*

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
        val scryptData = service.encrypt(code, pin, secret.toByteArray(), MedStickerCipherAttr.BRITNEY)

        println("medicalStickerEncryptionBritneyTest `secret` encrypted base64 ->${Base64Encoder.base64(scryptData.data)}")

        assertThat(Arrays.equals(scryptData.data, secret.toByteArray()))
                .isFalse()

        val decrypted = service.decrypt(pin, code, scryptData.data, MedStickerCipherAttr.BRITNEY)

        assertThat(String(decrypted))
                .isEqualTo(secret)
    }

    @Test
    fun medicalStickerEncryptionAdamTest() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val secret = "secret"

        val scryptData = service.encrypt(code, pin, secret.toByteArray(), MedStickerCipherAttr.ADAM)
        println("medicalStickerEncryptionAdamTest `secret` encrypted base64 ->${Base64Encoder.base64(scryptData.data)}")
        assertThat(Arrays.equals(scryptData.data, secret.toByteArray()))
                .isFalse()

        val decrypted = service.decrypt(pin, code, scryptData.data, MedStickerCipherAttr.ADAM)

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

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data, MedStickerCipherAttr.ADAM) }
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

        assertThatThrownBy { service.decrypt("wrongPin", code, scryptData.data, MedStickerCipherAttr.BRITNEY) }
                .isInstanceOf(DecryptionFailed::class.java)
                .hasMessageContaining("Failed to decrypt aes data")
    }

    @Test
    fun generateKeyBritneyShouldDriveKeyFromScrypt() {
        val version = MedStickerCipherAttr.BRITNEY
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
        val version = MedStickerCipherAttr.ADAM
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
        val version = MedStickerCipherAttr.BRITNEY

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
        val version = MedStickerCipherAttr.ADAM

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
        val version = MedStickerCipherAttr.BRITNEY

        val drived = service.deriveKey("yeeXCYff", "yzuygF6M", version)

        val key = service.generateKey("yeeXCYff", "yzuygF6M", version)

        val iv = service.generateIV(key, "yzuygF6M", version)
        println("driveKeyBritney code: \"yeeXCYff\", pin:\"yzuygF6M\" encrypted base64 -> key${Base64Encoder.base64(key)}, iv -> ${Base64Encoder.base64(iv)}")

        assertThat(Arrays.equals(key, drived.key))
                .isTrue()
                .withFailMessage("generated key should match drived key")

        assertThat(Arrays.equals(iv, drived.iv))

                .isTrue()
                .withFailMessage("generated iv should match drived key")
    }

    @Test
    fun driveKeyAdamShouldUsePinAndCodeToDriveTheKey() {
        val version = MedStickerCipherAttr.ADAM

        val drived = service.deriveKey("yeeXCYff", "yzuygF6M", version)

        val key = service.generateKey("yeeXCYff", "yzuygF6M", version)

        val iv = service.generateIV(key, "yzuygF6M", version)

        println("driveKeyAdam code: \"yeeXCYff\", ping:\"yzuygF6M\" encrypted base64 -> key${Base64Encoder.base64(key)}, iv -> ${Base64Encoder.base64(iv)}")

        assertThat(Arrays.equals(key, drived.key))
                .isTrue()
                .withFailMessage("generated key should match drived key")
        assertThat(Arrays.equals(iv, drived.iv))

                .isTrue()
                .withFailMessage("generated iv should match drived key")
    }

}