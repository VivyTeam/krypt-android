package com.vivy.symmetric

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesCbcPkcs7 : SymmetricEncryption {

    private val aesCipher: Cipher
        get() {
            try {
                return Cipher.getInstance("AES/CBC/PKCS7Padding")
            } catch (e: NoSuchAlgorithmException) {
                throw IllegalStateException("Failed to get cipher algorithm: AES/CBC/PKCS7Padding", e)
            } catch (e: NoSuchPaddingException) {
                throw IllegalStateException("Failed to get cipher algorithm: AES/CBC/PKCS7Padding", e)
            }

        }

    override fun encrypt(
        data: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray {
        val ivSpec = IvParameterSpec(iv)
        val skeySpec = SecretKeySpec(key, "AES")

        val cipher = aesCipher
        try {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Failed to initiate aes encrypt cipher", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw IllegalStateException("Failed to initiate aes encrypt cipher", e)
        }

        try {
            return cipher.doFinal(data)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalStateException("Failed to encrypt aes data", e)
        } catch (e: BadPaddingException) {
            throw IllegalStateException("Failed to encrypt aes data", e)
        }

    }

    override fun decrypt(
        encryptedData: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray {
        val ivSpec = IvParameterSpec(iv)
        val skeySpec = SecretKeySpec(key, "AES")

        val cipher = aesCipher
        try {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec)
        } catch (e: InvalidKeyException) {
            throw IllegalStateException("Failed to initiate aes decrypt cipher", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw IllegalStateException("Failed to initiate aes decrypt cipher", e)
        }

        try {
            return cipher.doFinal(encryptedData)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalStateException("Failed to decrypt aes data", e)
        } catch (e: BadPaddingException) {
            throw IllegalStateException("Failed to decrypt aes data", e)
        }

    }
}
