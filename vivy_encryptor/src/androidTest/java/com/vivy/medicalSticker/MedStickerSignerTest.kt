package com.vivy.medicalSticker

import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class MedStickerSignerTest {

    internal val service = MedStickerSigner

    @Test
    fun signTest() {
        assertThat(
            byteToHexString(service.signBytes("word".toByteArray(charset("UTF-8")), byteArrayOf(), byteArrayOf())).toUpperCase()
        )
            .isEqualTo("98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6")
    }

    @Test
    fun signBytes() {
        val signedBytes = service.signBytes("key".toByteArray(), "iv".toByteArray(), "salt".toByteArray())
        assertThat(byteToHexString(signedBytes).toUpperCase())
            .isEqualTo("3D8E7A243CEF60BF157EDB243C9930B2ACF39E7ED84C2A90506988F6919FF9DD")
    }

    @Test
    fun signAndBase64() {

        val signedBased = service.accessSignature(MedStickerCipherAttr("key".toByteArray(), "iv".toByteArray()), "someSaltWithExtraSpice".toByteArray())

        assertThat(signedBased)
            .isEqualTo("sha256/+vz8RNqVXkXPHqr4lRZ2tD09p83gLeQJB7cB1N3zS0=")
    }

    private fun byteToHexString(byteArray: ByteArray): String {

        val hexString = StringBuffer()

        for (i in byteArray.indices) {
            val hex = Integer.toHexString(0xff and byteArray[i].toInt())
            if (hex.length == 1) hexString.append('0')
            hexString.append(hex)
        }

        return hexString.toString()
    }
}