package com.vivy.asymmetric

import com.vivy.support.Base64Encoder
import com.vivy.support.KeyConverter
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature

class RSASignatureValidatorTest {

    val publicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzGVjnzCv8L1tCPZ5UtL1
/5d4ucTOgBVAy+6x5/9r2JoVnvzhtOIzaj0y1Bu4gP+AkDPNGuMwZvOXhPDMFHsv
HtGANQ/lV+WNMZyxF/B7EXwN7o1tuH9/M3Qe557N171dkPTLBc28mQ7PO0s+ZQPC
fmF62hLidZDtyNb+lhS5rYU8HTrtyqtQi2iezUoXCputhhufNfq0D75TD7MILokD
IA1uYL3+X40F2PCBybHFPHydFrl/T33u6IHrIh23nSx6ORWxdldklMWX6q9uTqEO
lA8G3CkDUaXCulBv/HlTixHoIFF2ejnhAI3vsFq5uYJ3JVGSK3LLm5AzTu24mFPg
6QIDAQAB
-----END PUBLIC KEY-----""".trim()


    private val fePayload = "eyJzdWIiOiI5MzQ0MDQ3ZmVmNDg4YzMyNzkwN2YxZDNkMTY3ZmEyOTg1ZDQ2MTAyMjllZGU5OTlkODEwZDg1MGY1NmFkMWQyIiwiZXhwIjoxNjA0NTg0NDA0LCJqdGkiOiJkMGNjYjQ5NC1iOTc1LTQ5MjYtOWMwOS1lMTRhOWI5ZGY0NGQiLCJqd2siOiJodHRwczovL29yZy52aXZ5LmNvbS9vYXV0aDIvdjEvY2VydHMvIiwia2lkIjoiZGJiMmU3YzcwOTQ3NWI1NTllYjM4NjA2YjVmODRjZTBiNzE4ZjhmZmZhMmZkOTdlZjZmMzNiZTczOWM5YWIzMyIsInZfYmF0Y2hfaWQiOiIzOGM0MDJiMy0xMGUwLTQ5ZDItYmEyMS02ZmFkMzhhYzkyNWIiLCJ2X3RhcmdldF9pZCI6IjEyZWM0N2JiLWY4OTAtNDUyNy1hNzExLWI2ZjY2NWMzYWU3NSIsInZfdGFyaWZmX2lkIjoiUExBVElOSVVNIiwidl9vcmdfaWQiOiJkMjE4OTVlYS01YTEzLTQzNWQtYjkxYi04ZTg0ODdmNGFkZmEiLCJ2X2RhdGFfcG9pbnRzIjoidXNlci5oZWFsdGguaW50ZXJlc3RzLmRpYWJldGVzPTF8dXNlci5oZWFsdGguaW50ZXJlc3RzLmJhY2tfcGFpbj0xIiwidl9jb25zdW1lcl9rZXkiOiI5eSRCJkUpSEBNY1FmVGpXblpxNHQ3dyF6JUMqRi1KYSJ9"
    private val jwtHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    private val feSignature = "woTPGYOJtmmqQW7hHEciwHAnKRItX7T-MFXVmknDzMwsTBxx6fZW5wvJwWBQPkFmtda6bSNNuLEbU43ulFpBv3to7KsAc7qSJbg9sap_Ru-imM0A1nQJU4iT24RuhXxiTKdWF9LnzUgLp0AKGbbv4vEC9BiEvD5zAesnvGKSma9xpQKnbtpJF0VoLb41sb0Uod9dVKKsqXMB8z9Qf-eV27H7cAkqlV1uuSsDKSpwY7orgtqyxUjRnSm_Tg7GWqrperX7H28QCidxWQaTgyb0jEViN-YI67xt0gLdP3loQ3I_Yx_mS5jI8uxqay4_-Lsxdf6izoTEuhT-etZjU_KXug"
    private val wrongFeSignature = "wrongsignuretext"
    private val feJwtBase64 = "$jwtHeader.$fePayload"

    private var signature: ByteArray = Base64Encoder.debase64Url(feSignature)
    private var wrongSignature: ByteArray = Base64Encoder.debase64Url(wrongFeSignature)

    @Test
    fun validatorReturnsTrueForValidSignature() {
        val keyConverter = KeyConverter()
        val isValid = RSASignatureValidator.verifyDigitalSignature(
            payload = feJwtBase64,
            signedPayload = signature,
            publicKey = keyConverter.toRSAPublicKey(publicKey)
        )
        assertEquals(true, isValid)
    }

    @Test
    fun validatorReturnsFalseForWrongSignature() {
        val keyConverter = KeyConverter()
        val isValid = RSASignatureValidator.verifyDigitalSignature(
            payload = feJwtBase64,
            signedPayload = wrongSignature,
            publicKey = keyConverter.toRSAPublicKey(publicKey)
        )
        assertEquals(true, isValid)
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

        val isValid = RSASignatureValidator.verifyDigitalSignature(message, signatureBytes, pubKey)
        assertEquals(false, isValid)
    }
}
