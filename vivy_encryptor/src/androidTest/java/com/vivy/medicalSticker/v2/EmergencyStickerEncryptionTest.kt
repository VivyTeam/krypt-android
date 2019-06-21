package com.vivy.medicalSticker.v2

import com.vivy.e2e.DecryptionFailed
import com.vivy.medicalSticker.MedStickerCipherAttr.Companion.CHARLIE
import com.vivy.medicalSticker.MedStickerKeyGenerator
import org.assertj.core.api.Assertions.assertThat
import org.junit.Before
import org.junit.Test
import java.util.Arrays
import org.assertj.core.api.Assertions.assertThatThrownBy
import java.security.SecureRandom

class EmergencyStickerEncryptionTest{
    val service = EmergencyStickerEncryption

    @Before
    fun setup() {
        service setDebugTo false
    }

    @Test
    fun generateFingerprintSecretShouldDriveKeyFromScrypt(){
        val pin = "someRandomPin"
        val firstSalt = "someRandomSalt"

        val fingerprintSecret = service.getFingerprintSecret(pin, firstSalt)

        val generatedFingerprintSecret = MedStickerKeyGenerator.getGenSCryptKey(
            pin.toByteArray(),
            firstSalt.toByteArray(),
            EmergencyStickerEncryption.CPU_COST,
            EmergencyStickerEncryption.MEMORY_COST,
            EmergencyStickerEncryption.PARALLELIZATION_PARAM,
            EmergencyStickerEncryption.FINGER_PRINT_SECRET_LENGTH
        )

        assertThat(Arrays.equals(fingerprintSecret, generatedFingerprintSecret))
            .withFailMessage("generated key should be exactly as scrypt key")
            .isTrue()

        assertThat(fingerprintSecret.size).isEqualTo(EmergencyStickerEncryption.FINGER_PRINT_SECRET_LENGTH)
    }

    @Test
    fun generatePinFingerprintShouldDriveKeyFromScrypt(){
        val pin = "someRandomPin"
        val backendSecret = "someRandomBackendSecret"
        val secondSalt = "someRandomSecondSalt"

        val pinFingerprint = service.getPinFingerprint(pin, backendSecret, secondSalt)

        val finalPin = pin + backendSecret
        val generatedPinFingerprint = MedStickerKeyGenerator.getGenSCryptKey(
            finalPin.toByteArray(),
            secondSalt.toByteArray(),
            EmergencyStickerEncryption.CPU_COST,
            EmergencyStickerEncryption.MEMORY_COST,
            EmergencyStickerEncryption.PARALLELIZATION_PARAM,
            EmergencyStickerEncryption.PIN_FINGER_PRINT_LENGTH
        )

        assertThat(Arrays.equals(pinFingerprint, generatedPinFingerprint))
            .withFailMessage("generated key should be exactly as scrypt key")
            .isTrue()

        assertThat(pinFingerprint.size).isEqualTo(EmergencyStickerEncryption.PIN_FINGER_PRINT_LENGTH)
    }

    @Test
    fun validateByteArrayIsDividedEqually(){
        val byteArray1 = getRandomByteArray(256)
        val byteArray2 = getRandomByteArray(256)
        val addedByteArray = byteArray1 + byteArray2

        val dividedArray = service.getKeyAndFingerprintFilePair(addedByteArray)

        assertThat(dividedArray.key).isEqualTo(byteArray1)
        assertThat(dividedArray.fingerprintFile).isEqualTo(byteArray2)
    }

    @Test
    fun emergencyStickerEncryptionTest() {
        val pin = "someRandomPin"
        val backendSecret = "someRandomBackendSecret"
        val secondSalt = "someRandomSecondSalt"
        val secret = "secret"

        val encryptedData = service.encrypt(pin, backendSecret, secondSalt, secret.toByteArray())

        assertThat(Arrays.equals(encryptedData.data, secret.toByteArray()))
            .isFalse()

        val decrypted = service.decrypt(pin, backendSecret, secondSalt, encryptedData.attr.iv, encryptedData.data, CHARLIE)

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

        val encryptedData = service.encrypt(pin, backendSecret, secondSalt, secret.toByteArray())

        assertThatThrownBy { service.decrypt("wrongPin", backendSecret, secondSalt, encryptedData.attr.iv, encryptedData.data, CHARLIE) }
            .isInstanceOf(DecryptionFailed::class.java)
            .hasNoCause()
    }

    private fun getRandomByteArray(length:Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes
    }
}