package com.vivy.qr.decryption

import com.vivy.support.Base64Encoder
import com.vivy.support.Gzip
import com.vivy.symmetric.AesGcmNoPadding

object QrDecryptor {
    private val base64Encoder = Base64Encoder
    private val aesGcmNoPadding = AesGcmNoPadding()
    private val gzip = Gzip()

    fun decrypt(qr: String,
                iv: String,
                key: String
    ): ByteArray {
        val decodedAesQR = base64Encoder.debase64(qr)
        val decodedIV = base64Encoder.debase64(iv)
        val decodedDecryptionKey = base64Encoder.debase64(key)
        val decryptedQr = aesGcmNoPadding.decrypt(
            encryptedData = decodedAesQR,
            iv = decodedIV,
            key = decodedDecryptionKey
        )
        return gzip.gunzip(decryptedQr)
    }
}
