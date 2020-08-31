package com.vivy.qr.decryption


import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import javax.crypto.AEADBadTagException


class QrDecryptorTest {

    private val qrDecryptor = QrDecryptor

    private val invalidKey = "3TvmmGijjNpQ4AYtdTjdweEFieY7SjI0qO3Y5k9kVLc="
    private val invalideIV = "MB3lB1KKhTNtArNSU31Z3w=="
    private val qr = "07OdLDc94F/2vUBwTQrxLibI/vWT9Wz/wQel4l1yv19EKVo5ntkzz4y/qDYSamqKgKnvI3SCY1qvsMxJxfNC6z43ebrTxYocnJNcD8cdEs5Yig7KRabxLxHAxnRkEzHo1ZFLNvPWXKcIEqeOVhgepj1ED2P7hrl4lttwpD5HsK3+8culLn1x+fByMFqvPx0hrq0RucOxRYydauFaRkraaP7uHYyfMJvCTlbnmjl1XvoFOikJ73cUgcYzGhHLfDTUDZB+O6NDIXCbXxhtMSzbhtYr+j8QhWMwwmfEyHcDvKVnPBlN41oRrmuUT8ffP2HeiP6MFWWulDLxskQgBvFtrcejMkmZ74r8NznsgP47EYTXpZc5t9hoqTptNwSxNZRbFyTlk4tSKElUMLTpk9ZsvQrRmZKtUwHsaLOonR7yqBIhgMJwvkwslqzaPugB9mc1PKUO5rxnL+CWfdtvYXIf0AQR0UxZPJb6DygaqL3oUZkUfOrdqcikVKUEv0fGlcT67DH6CyoKyA8Pd0E+/zyJUzkoWhCBJig4ljfR+sxDOSvk8CPbU2gzyMC325BFXZ3lnyYwFtesMRBGS3prOvB92raeanOQruiRoCh9ZfZFoSlDFTXHLF/D/tIXMFwfWYvr3NwWlEQX46g1OjNwHNS19760+y8yowtcsvpQXH3ifL6aTGpud8nuqGxiCiITXsliIJY/Rco4S8fn63mWfsR2JB69/vexxoMZTZgLe8tWQHskVgRIUdWjliVDAHwv6Q8HASU3cZPh1i2CGJaJayTl8qXGu+mYGXYuSz0r5I6f8IBKun2xRgrH3bt60MaRmCl4WWO6v1bs2/YFppNu07AFlraJz1HtBwfN/aVkbU8Cd7hbzfD4W6v6qqo0pGV3JplLFTgScusQld3QyDqDNyAc3FAYvYANywIddeACggu/79+WMzjll535NgE08r34SPJL8ipPLTDKj4hFupRWHYfVjIMZ57S6ZECVFaBOy8JgUjL2qLQj4wYLUASJBvgcsucPMnVVD9AIp4kdDuJ4Z/8mxdBHwPhwwpRYK8iTjkj4r9ayXr2Vsa8cB8kUhcgyldFYdRcvYI/RUelyvCunfWPBSIU86wyEeSRGiNcW7/4yAQxxQgAcUGOL/xKnZracaLgBVIJwwQ8FCXfeTmzPfhJ52C/NA6sqCufEIBRV8tMnl9KlWCt/rrEnbD1xqLH4A9mFtOqNW5D3vHYSeI0a842JR5gBo1/O2UiEmaGGDTWHnRHQtaDEKaZzXg/rMDZw6H3LHxLnlzjPjlL5RpFFb0+ardroNBtu8lbqIxRZez6MyleHPrGwMQ8rxH/ANFmm4zlZAXfFnWAnaE77mvojBRMRFN4nCf3Kp3wWtb74ecaUE8l9eXbGqTqrmeehuMHGmBMyTMrcA1HLR6Prb6QWmooPntHNYA/zB+/BNYcP9BfHosVXSphj/sZiYUPULaqEAltzbfv9Ot5lcbQDQYL92ZcYyO/0SlxZZ69YtPzcEisi9Z5WT4Q4eId7DoKOyf1amthyWddabo2DDflaR7Di0ixMBqmM43n6P9R96ixW/HIySWT6/3FlYJBp53TNH3Z9Ld2eWreS5wht6SQqPB0Ce51Uwm7Pvtdo3tukgfebB3CEBKI8Cwgc9IonDpmf9t2q4QFhDeAGLrkYZZmsRFHykwgMch+EFw=="
    private val validDecryptionKey = "mqwNOaOjojvKcvWsMWkK4pCU8r0OAyLHIP1OLHebUts="
    private val initializationVector = "vzG26QOi2vLx2otVYPPmpA=="


    private val feJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5MzQ0MDQ3ZmVmNDg4YzMyNzkwN2YxZDNkMTY3ZmEyOTg1ZDQ2MTAyMjllZGU5OTlkODEwZDg1MGY1NmFkMWQyIiwiZXhwIjoxNjA0NTg0NDA0LCJqdGkiOiJkMGNjYjQ5NC1iOTc1LTQ5MjYtOWMwOS1lMTRhOWI5ZGY0NGQiLCJqd2siOiJodHRwczovL29yZy52aXZ5LmNvbS9vYXV0aDIvdjEvY2VydHMvIiwia2lkIjoiZGJiMmU3YzcwOTQ3NWI1NTllYjM4NjA2YjVmODRjZTBiNzE4ZjhmZmZhMmZkOTdlZjZmMzNiZTczOWM5YWIzMyIsInZfYmF0Y2hfaWQiOiIzOGM0MDJiMy0xMGUwLTQ5ZDItYmEyMS02ZmFkMzhhYzkyNWIiLCJ2X3RhcmdldF9pZCI6IjEyZWM0N2JiLWY4OTAtNDUyNy1hNzExLWI2ZjY2NWMzYWU3NSIsInZfdGFyaWZmX2lkIjoiUExBVElOSVVNIiwidl9vcmdfaWQiOiJkMjE4OTVlYS01YTEzLTQzNWQtYjkxYi04ZTg0ODdmNGFkZmEiLCJ2X2RhdGFfcG9pbnRzIjoidXNlci5oZWFsdGguaW50ZXJlc3RzLmRpYWJldGVzPTF8dXNlci5oZWFsdGguaW50ZXJlc3RzLmJhY2tfcGFpbj0xIiwidl9jb25zdW1lcl9rZXkiOiI5eSRCJkUpSEBNY1FmVGpXblpxNHQ3dyF6JUMqRi1KYSJ9.woTPGYOJtmmqQW7hHEciwHAnKRItX7T-MFXVmknDzMwsTBxx6fZW5wvJwWBQPkFmtda6bSNNuLEbU43ulFpBv3to7KsAc7qSJbg9sap_Ru-imM0A1nQJU4iT24RuhXxiTKdWF9LnzUgLp0AKGbbv4vEC9BiEvD5zAesnvGKSma9xpQKnbtpJF0VoLb41sb0Uod9dVKKsqXMB8z9Qf-eV27H7cAkqlV1uuSsDKSpwY7orgtqyxUjRnSm_Tg7GWqrperX7H28QCidxWQaTgyb0jEViN-YI67xt0gLdP3loQ3I_Yx_mS5jI8uxqay4_-Lsxdf6izoTEuhT-etZjU_KXug"
    private val beJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5MzQ0MDQ3ZmVmNDg4YzMyNzkwN2YxZDNkMTY3ZmEyOTg1ZDQ2MTAyMjllZGU5OTlkODEwZDg1MGY1NmFkMWQyIiwiZXhwIjoxNjA0NTg0NDA0LCJqdGkiOiI0MzE3NWRkNy0yODRiLTRjMDEtODY0YS0wZGMyYmY1YmUxZDkiLCJqd2siOiJodHRwczovL29yZy52aXZ5LmNvbS9vYXV0aDIvdjEvY2VydHMvIiwia2lkIjoiZGJiMmU3YzcwOTQ3NWI1NTllYjM4NjA2YjVmODRjZTBiNzE4ZjhmZmZhMmZkOTdlZjZmMzNiZTczOWM5YWIzMyIsInZfb3JnX2lkIjoiZDIxODk1ZWEtNWExMy00MzVkLWI5MWItOGU4NDg3ZjRhZGZhIiwidl90YXJpZmZfaWQiOiJQTEFUSU5JVU0ifQ.KcLCfyf1teiWpytr0KYlqLdANPO5eoMu6ZnEg1bne96F7nK3NIe-Bn9dRT1JIDMtX1CJxS3MeGTlREZxIvUv_p04di6pAqWLF0gibhFBM35zCJbXToPUd1Qt91bnpuemWypAKDmR6MKAXgdmE9fhyA7TGiK_9pe3dZE2UkVa622svZmzs5QYijR4h5o_3qjxP98Z-bkvLyPMpDEkVPslMW4Xc7c2efibkPOCbHrZPbiqQQVUH3swXtjGnbth7Ipkhx_WZ3WYvUkU_7YwUwnoY3EgcqrfTTj68H3erxM3epWIcCI60HyskT9eo7Dyd0nsYqYFHfBA8DaZVaRu-iIp2w"
    private val plainQRJsonString = "{\"fe_jwt\":\"$feJwt\",\"be_jwt\":\"$beJwt\"}"

    @Test
    fun whenValidKeyAndValidIVThenDecryptQrCodeShouldSuccess() {
        val decryptedQrCode = qrDecryptor.decrypt(
            qr = qr,
            key = validDecryptionKey,
            iv = initializationVector
        )
        assertThat(String(decryptedQrCode))
            .isEqualTo(plainQRJsonString)
    }


    @Test
    fun whenDecryptQrCodeWithInvalidKeyThenExceptionShouldBeThrown() {
        Assertions.assertThatThrownBy {
            qrDecryptor.decrypt(
                qr = qr,
                key = invalidKey,
                iv = initializationVector
            )
        }.isInstanceOf(IllegalStateException::class.java)
            .hasCauseExactlyInstanceOf(AEADBadTagException::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }

    @Test
    fun whenDecryptQrCodeWithInvalidIVThenExceptionShouldBeThrown() {
        Assertions.assertThatThrownBy {
            qrDecryptor.decrypt(
                qr = qr,
                key = validDecryptionKey,
                iv = invalideIV
            )
        }.isInstanceOf(IllegalStateException::class.java)
            .hasCauseExactlyInstanceOf(AEADBadTagException::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }
}
