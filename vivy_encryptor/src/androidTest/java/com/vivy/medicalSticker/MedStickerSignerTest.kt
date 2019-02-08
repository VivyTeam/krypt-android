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
            .isEqualTo("17757D722A51BD2DAC96A682C40FBF95BC883BEAC323550F96FC7F5D91893741")
    }

    @Test
    fun signAndBase64() {

        val signedBased = service.accessSignature(MedStickerCipherAttr("key".toByteArray(), "iv".toByteArray()), "someSaltWithExtraSpice".toByteArray())

        assertThat(signedBased)
            .isEqualTo("sha2566CxmnzC0V7ZOUyiW03pA2y0vOfdU5bLm2L/2/55byCI=")
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