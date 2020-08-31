package com.vivy.qr.decryption

import com.vivy.qr.decryption.QrConstant.ValidData
import com.vivy.qr.decryption.QrConstant.InvalidData
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import javax.crypto.AEADBadTagException


class QrDecryptorTest {

    private val qrDecryptor = QrDecryptor

    @Test
    fun whenValidKeyAndValidIVThenDecryptQrCodeShouldSuccess() {
        val decryptedQrCode = qrDecryptor.decrypt(
            qr = ValidData.QR,
            key = ValidData.KEY,
            iv = ValidData.IV
        )
        assertThat(String(decryptedQrCode))
            .isEqualTo(ValidData.PLAIN_QRJSON_STRING)
    }


    @Test
    fun whenDecryptQrCodeWithInvalidKeyThenExceptionShouldBeThrown() {
        Assertions.assertThatThrownBy {
            qrDecryptor.decrypt(
                qr = ValidData.QR,
                key = InvalidData.KEY,
                iv = ValidData.IV
            )
        }.isInstanceOf(IllegalStateException::class.java)
            .hasCauseExactlyInstanceOf(AEADBadTagException::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }

    @Test
    fun whenDecryptQrCodeWithInvalidIVThenExceptionShouldBeThrown() {
        Assertions.assertThatThrownBy {
            qrDecryptor.decrypt(
                qr = ValidData.QR,
                key = ValidData.KEY,
                iv = InvalidData.IV
            )
        }.isInstanceOf(IllegalStateException::class.java)
            .hasCauseExactlyInstanceOf(AEADBadTagException::class.java)
            .hasMessageContaining("Failed to decrypt aes data")
    }
}
