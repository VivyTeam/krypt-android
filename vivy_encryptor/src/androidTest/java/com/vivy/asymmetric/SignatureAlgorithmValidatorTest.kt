package com.vivy.asymmetric

import com.vivy.support.Base64Encoder
import com.vivy.support.KeyConverter
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature

class SignatureAlgorithmValidatorTest {

    object RS256 {
        val alg = SignatureAlgorithm.RS256
        val publicKey =
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzGVjnzCv8L1tCPZ5UtL1
/5d4ucTOgBVAy+6x5/9r2JoVnvzhtOIzaj0y1Bu4gP+AkDPNGuMwZvOXhPDMFHsv
HtGANQ/lV+WNMZyxF/B7EXwN7o1tuH9/M3Qe557N171dkPTLBc28mQ7PO0s+ZQPC
fmF62hLidZDtyNb+lhS5rYU8HTrtyqtQi2iezUoXCputhhufNfq0D75TD7MILokD
IA1uYL3+X40F2PCBybHFPHydFrl/T33u6IHrIh23nSx6ORWxdldklMWX6q9uTqEO
lA8G3CkDUaXCulBv/HlTixHoIFF2ejnhAI3vsFq5uYJ3JVGSK3LLm5AzTu24mFPg
6QIDAQAB
-----END PUBLIC KEY-----""".trim()

        private const val FE_PAYLOAD = "eyJzdWIiOiI5MzQ0MDQ3ZmVmNDg4YzMyNzkwN2YxZDNkMTY3ZmEyOTg1ZDQ2MTAyMjllZGU5OTlkODEwZDg1MGY1NmFkMWQyIiwiZXhwIjoxNjA0NTg0NDA0LCJqdGkiOiJkMGNjYjQ5NC1iOTc1LTQ5MjYtOWMwOS1lMTRhOWI5ZGY0NGQiLCJqd2siOiJodHRwczovL29yZy52aXZ5LmNvbS9vYXV0aDIvdjEvY2VydHMvIiwia2lkIjoiZGJiMmU3YzcwOTQ3NWI1NTllYjM4NjA2YjVmODRjZTBiNzE4ZjhmZmZhMmZkOTdlZjZmMzNiZTczOWM5YWIzMyIsInZfYmF0Y2hfaWQiOiIzOGM0MDJiMy0xMGUwLTQ5ZDItYmEyMS02ZmFkMzhhYzkyNWIiLCJ2X3RhcmdldF9pZCI6IjEyZWM0N2JiLWY4OTAtNDUyNy1hNzExLWI2ZjY2NWMzYWU3NSIsInZfdGFyaWZmX2lkIjoiUExBVElOSVVNIiwidl9vcmdfaWQiOiJkMjE4OTVlYS01YTEzLTQzNWQtYjkxYi04ZTg0ODdmNGFkZmEiLCJ2X2RhdGFfcG9pbnRzIjoidXNlci5oZWFsdGguaW50ZXJlc3RzLmRpYWJldGVzPTF8dXNlci5oZWFsdGguaW50ZXJlc3RzLmJhY2tfcGFpbj0xIiwidl9jb25zdW1lcl9rZXkiOiI5eSRCJkUpSEBNY1FmVGpXblpxNHQ3dyF6JUMqRi1KYSJ9"
        private const val JWT_HEADER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        private const val FE_SIGNATURE = "woTPGYOJtmmqQW7hHEciwHAnKRItX7T-MFXVmknDzMwsTBxx6fZW5wvJwWBQPkFmtda6bSNNuLEbU43ulFpBv3to7KsAc7qSJbg9sap_Ru-imM0A1nQJU4iT24RuhXxiTKdWF9LnzUgLp0AKGbbv4vEC9BiEvD5zAesnvGKSma9xpQKnbtpJF0VoLb41sb0Uod9dVKKsqXMB8z9Qf-eV27H7cAkqlV1uuSsDKSpwY7orgtqyxUjRnSm_Tg7GWqrperX7H28QCidxWQaTgyb0jEViN-YI67xt0gLdP3loQ3I_Yx_mS5jI8uxqay4_-Lsxdf6izoTEuhT-etZjU_KXug"
        private const val WRONG_FE_SIGNATURE = "wrongsignuretext"
        const val FE_JWT_BASE_64 = "$JWT_HEADER.$FE_PAYLOAD"

        val signature: ByteArray = Base64Encoder.debase64Url(FE_SIGNATURE)
        val wrongSignature: ByteArray = Base64Encoder.debase64Url(WRONG_FE_SIGNATURE)
    }

    object RS512 {
        val alg = SignatureAlgorithm.RS512
        val publicKey =
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----""".trim()

        private const val FE_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        private const val JWT_HEADER = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9"
        private const val FE_SIGNATURE = "JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"
        private const val WRONG_FE_SIGNATURE = "wrongsignuretext"
        const val FE_JWT_BASE_64 = "$JWT_HEADER.$FE_PAYLOAD"

        val signature: ByteArray = Base64Encoder.debase64Url(FE_SIGNATURE)
        val wrongSignature: ByteArray = Base64Encoder.debase64Url(WRONG_FE_SIGNATURE)
    }

    @Test
    fun validatorReturnsTrueForValidRS256Signature() {
        val keyConverter = KeyConverter()
        val isValid = SignatureAlgorithmValidator.verifyDigitalSignature(
            payload = RS256.FE_JWT_BASE_64,
            signedPayload = RS256.signature,
            publicKey = keyConverter.toRSAPublicKey(RS256.publicKey),
            algorithm = RS256.alg
        )
        assertEquals(true, isValid)
    }

    @Test
    fun validatorReturnsFalseForWrongRS256Signature() {
        val keyConverter = KeyConverter()
        val isValid = SignatureAlgorithmValidator.verifyDigitalSignature(
            payload = RS256.FE_JWT_BASE_64,
            signedPayload = RS256.wrongSignature,
            publicKey = keyConverter.toRSAPublicKey(RS256.publicKey),
            algorithm = RS256.alg
        )
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

        val isValid = SignatureAlgorithmValidator.verifyDigitalSignature(message, signatureBytes, pubKey, SignatureAlgorithm.RS512)
        assertEquals(false, isValid)
    }


// ------------  RS512 --------------

    @Test
    fun validatorReturnsTrueForValidRS512Signature() {
        val keyConverter = KeyConverter()
        val isValid = SignatureAlgorithmValidator.verifyDigitalSignature(
            payload = RS512.FE_JWT_BASE_64,
            signedPayload = RS512.signature,
            publicKey = keyConverter.toRSAPublicKey(RS512.publicKey),
            algorithm = RS512.alg
        )
        assertEquals(true, isValid)
    }

    @Test
    fun validatorReturnsFalseForWrongRS512Signature() {
        val keyConverter = KeyConverter()
        val isValid = SignatureAlgorithmValidator.verifyDigitalSignature(
            payload = RS512.FE_JWT_BASE_64,
            signedPayload = RS512.wrongSignature,
            publicKey = keyConverter.toRSAPublicKey(RS512.publicKey),
            algorithm = RS512.alg
        )
        assertEquals(false, isValid)
    }
}
