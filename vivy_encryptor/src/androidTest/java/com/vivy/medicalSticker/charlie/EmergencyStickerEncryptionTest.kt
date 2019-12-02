package com.vivy.medicalSticker.charlie

import com.vivy.e2e.DecryptionFailed
import com.vivy.medicalSticker.MedStickerCipherAttr
import com.vivy.medicalSticker.MedStickerKeyGenerator
import com.vivy.medicalSticker.charlie.EmergencyStickerEncryption.CHARLIE_STATIC_SALT
import com.vivy.medicalSticker.charlie.EmergencyStickerEncryption.HASH_LENGTH
import com.vivy.support.SecureRandomGenerator
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.Before
import org.junit.Test
import java.util.*

class EmergencyStickerEncryptionTest {
    val service = EmergencyStickerEncryption

    @Before
    fun setup() {
        service setDebugTo false
    }

    @Test
    fun generateFingerprintSecretShouldDriveKeyFromScrypt() {
        val pin = "someRandomPin"

        val fingerprintSecret = service.getFingerprintSecret(pin)

        val generatedFingerprintSecret = MedStickerKeyGenerator.getGenSCryptKey(
                pin.toByteArray(),
                CHARLIE_STATIC_SALT.toByteArray(),
                EmergencyStickerEncryption.CPU_COST,
                EmergencyStickerEncryption.MEMORY_COST,
                EmergencyStickerEncryption.PARALLELIZATION_PARAM,
                HASH_LENGTH
        ).asFingerprint()

        assertThat(fingerprintSecret).isEqualTo(generatedFingerprintSecret)
                .withFailMessage("generated key should be exactly as scrypt key")
    }

    @Test
    fun generatePinFingerprintShouldDriveKeyFromScrypt() {
        val pin = "someRandomPin"
        val backendSecret = "someRandomBackendSecret"
        val secondSalt = "someRandomSecondSalt"

        val pinFingerprint = service.getKeyAndFingerprintFile(pin, backendSecret, secondSalt)

        val finalPin = pin + backendSecret
        val generatedPinFingerprint = MedStickerKeyGenerator.getGenSCryptKey(
                finalPin.toByteArray(),
                secondSalt.toByteArray(),
                EmergencyStickerEncryption.CPU_COST,
                EmergencyStickerEncryption.MEMORY_COST,
                EmergencyStickerEncryption.PARALLELIZATION_PARAM,
                HASH_LENGTH
        )

        assertThat(Arrays.equals(pinFingerprint.key, generatedPinFingerprint.copyOfRange(0, HASH_LENGTH / 2)))
                .withFailMessage("generated key should be exactly as scrypt key")
                .isTrue()

        assertThat(pinFingerprint.fingerprintFile)
                .withFailMessage("generated key should be exactly as scrypt key")
                .isEqualTo(generatedPinFingerprint.copyOfRange(HASH_LENGTH / 2, HASH_LENGTH).asFingerprint())
    }

    @Test
    fun emergencyStickerEncryptionTest() {
        val pin = "someRandomPin"
        val backendSecret = "someRandomBackendSecret"
        val secondSalt = "someRandomSecondSalt"
        val secret = "secret"

        val encryptedData = service.encrypt(pin, backendSecret, secondSalt, getRandomAesIv(), secret.toByteArray())

        assertThat(Arrays.equals(encryptedData.data, secret.toByteArray()))
                .isFalse()

        val decrypted = service.decrypt(pin, backendSecret, secondSalt, encryptedData.attr.iv, encryptedData.data)

        assertThat(String(decrypted))
                .isEqualTo(secret)
    }

    @Test
    fun errorsShouldBeSwallowedOnProduction() {
        val pin = "someRandomPin"
        val backendSecret = "someRandomBackendSecret"
        val secondSalt = "someRandomSecondSalt"
        val secret = "secret"

        service setDebugTo false

        val encryptedData = service.encrypt(pin, backendSecret, secondSalt, secret.toByteArray(), getRandomAesIv())

        assertThatThrownBy { service.decrypt("wrongPin", backendSecret, secondSalt, encryptedData.attr.iv, encryptedData.data) }
                .isInstanceOf(DecryptionFailed::class.java)
                .hasNoCause()
    }

    private fun getRandomAesIv(): ByteArray {
        return SecureRandomGenerator().bytes(EmergencyStickerEncryption.AES_IV_LENGTH)
    }

    private fun ByteArray.asFingerprint(): String {
        return "${MedStickerCipherAttr.CHARLIE}:" + this.joinToString("") {
            java.lang.String.format("%02x", it)
        }
    }
}