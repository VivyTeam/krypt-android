package com.vivy.asymmetric

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature

class RSASignatureValidatorTest {

    @Test
    fun validatorReturnsTrueForValidSignature() {
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(512, SecureRandom())
        val keyPair = keyGenerator.genKeyPair()
        val privKey = keyPair.private
        val pubKey = keyPair.public

        val message = "some text"
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privKey, SecureRandom())
        signature.update(message.toByteArray())
        val signatureBytes = signature.sign()

        val isValid = RSASignatureValidator.verifyDigitalSignature(message, Base64.encodeToString(signatureBytes, 0), pubKey)
        assertEquals(true, isValid)
    }

    @Test
    fun validatorReturnsFalseForWrongSignature() {
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(512, SecureRandom())
        val keyPair = keyGenerator.genKeyPair()
        val privKey = keyPair.private
        val pubKey = keyPair.public

        val message = "some text"
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privKey, SecureRandom())

        signature.update("new message".toByteArray())
        val wrongSignatureBytes = signature.sign()

        val isValid = RSASignatureValidator.verifyDigitalSignature(message, Base64.encodeToString(wrongSignatureBytes, 0), pubKey)
        assertEquals(false, isValid)
    }

    @Test
    fun validatorReturnsFalseForWrongSigningAlgorithm() {
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(512, SecureRandom())
        val keyPair = keyGenerator.genKeyPair()
        val privKey = keyPair.private
        val pubKey = keyPair.public

        val message = "some text"
        val signature = Signature.getInstance("SHA224withRSA")
        signature.initSign(privKey, SecureRandom())
        signature.update(message.toByteArray())
        val signatureBytes = signature.sign()

        val isValid = RSASignatureValidator.verifyDigitalSignature(message, Base64.encodeToString(signatureBytes, 0), pubKey)
        assertEquals(false, isValid)
    }
}
