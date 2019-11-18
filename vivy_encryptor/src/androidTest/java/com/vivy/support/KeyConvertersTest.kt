package com.vivy.support


import com.vivy.e2e.RsaEcbOeapSha256AesGcmNoPadding
import com.vivy.e2e.RsaEcbPkcs1AesCbcPkcs7
import junit.framework.TestCase.assertEquals
import org.junit.Test



class KeyConvertersTest {

    private val PKC1_PK: String="-----BEGIN RSA PRIVATE KEY-----\n" +
        "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\n" +
        "-----END RSA PRIVATE KEY-----"


    private val PKC1_PBK: String="-----BEGIN PUBLIC KEY-----\n" +
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv1PCQyoC/MQYdqszsCoi\n" +
        "6PPHdhP5GhS9HAJWKjXMrjUrgcTcgG0FauelL06jPPh1Y0WDwOEg5H9mw5z973g8\n" +
        "lK2OzLp+pT6A/XsSgKruEXU4uAMREc7fONPMoBWeb6vTlQHTPQK5Eunttj+cN4EF\n" +
        "t3Xp4tYjr1H63PqfjTBThHNW2Qq3Ni9JZP3akW6mwMlA5DwVXzKGYR85Y1xqAaFT\n" +
        "AF1X4dWc1W2yXVlGGhLQJlhQJ6c5nzL4eWsupiODPwjSolID2j1ZQpQyc4JWOJyQ\n" +
        "9R+D4NF7zVICwXXzXR/8zm8bIxlq8KUQo1U15G9+WLpdRyaayhKLCAQGE9Fz6RL3\n" +
        "UYVc0/1MpYryFZeeDZ48KLNMzJbwElq4pd4Scb8TrpU2CcE79QMNwGlUGL1B7UrL\n" +
        "3Dsuod2+of2KnBZog7FhceDkjDRjdr6r893mo8bb6C3pX3pc0tftj8jnYxdc8jnd\n" +
        "l/DT372toX28gsSk0SAf02sJP4RQsOzs/xM+uDFxUoRltK1jXkg9J7RlYSdPKtez\n" +
        "afP9kSOLCE8WVPE8V7JWLGkd4fJeRYZ/0fhpF8Px2V4+gQ7Z3MmUTSIDXUB5MJTr\n" +
        "SF5DxFTtviIHY2cDSCkWUIrlnM9Is8g+mD41qH71danykfeeYGCf0+JeIR0/fKFW\n" +
        "K25oKMRQrG3oqzakk/CiaZECAwEAAQ==\n" +
        "-----END PUBLIC KEY-----"

    private val PKCS8_PK:String ="-----BEGIN PRIVATE KEY-----\n" +
        "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\n" +
        "17OrnUZoh08UdKrwi0+nYqMyU1F+Boc=\n" +
        "-----END PRIVATE KEY-----"

    private val PKCS8_PBK:String="-----BEGIN PUBLIC KEY-----\n" +
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv1PCQyoC/MQYdqszsCoi\n" +
        "6PPHdhP5GhS9HAJWKjXMrjUrgcTcgG0FauelL06jPPh1Y0WDwOEg5H9mw5z973g8\n" +
        "lK2OzLp+pT6A/XsSgKruEXU4uAMREc7fONPMoBWeb6vTlQHTPQK5Eunttj+cN4EF\n" +
        "t3Xp4tYjr1H63PqfjTBThHNW2Qq3Ni9JZP3akW6mwMlA5DwVXzKGYR85Y1xqAaFT\n" +
        "AF1X4dWc1W2yXVlGGhLQJlhQJ6c5nzL4eWsupiODPwjSolID2j1ZQpQyc4JWOJyQ\n" +
        "9R+D4NF7zVICwXXzXR/8zm8bIxlq8KUQo1U15G9+WLpdRyaayhKLCAQGE9Fz6RL3\n" +
        "UYVc0/1MpYryFZeeDZ48KLNMzJbwElq4pd4Scb8TrpU2CcE79QMNwGlUGL1B7UrL\n" +
        "3Dsuod2+of2KnBZog7FhceDkjDRjdr6r893mo8bb6C3pX3pc0tftj8jnYxdc8jnd\n" +
        "l/DT372toX28gsSk0SAf02sJP4RQsOzs/xM+uDFxUoRltK1jXkg9J7RlYSdPKtez\n" +
        "afP9kSOLCE8WVPE8V7JWLGkd4fJeRYZ/0fhpF8Px2V4+gQ7Z3MmUTSIDXUB5MJTr\n" +
        "SF5DxFTtviIHY2cDSCkWUIrlnM9Is8g+mD41qH71danykfeeYGCf0+JeIR0/fKFW\n" +
        "K25oKMRQrG3oqzakk/CiaZECAwEAAQ==\n" +
        "-----END PUBLIC KEY-----"

    private val rsaEcbPkcs1AesCbcPkcs7 = RsaEcbPkcs1AesCbcPkcs7()
    private val rsaEcbOeapSha256AesGcmNoPadding= RsaEcbOeapSha256AesGcmNoPadding()
    @Test
    fun convertFromPKCS1ToPCS2Gcm(){
        val keyConverter = KeyConverter()
        val privateKey = keyConverter.PKC1ToPKCS8PrivateKey(PKC1_PK)
        val publicKey=keyConverter.toRSAPublicKey(PKC1_PBK)
        val text = "secret"

        val encrypted = rsaEcbPkcs1AesCbcPkcs7.encrypt(publicKey, text.toByteArray())

        val decrypted = rsaEcbPkcs1AesCbcPkcs7.decrypt(privateKey, encrypted)

        assertEquals(text, String(decrypted))

    }

    @Test
    fun convertFromPKCS1ToPCS2CBC(){
        val keyConverter = KeyConverter()
        val privateKey = keyConverter.PKC1ToPKCS8PrivateKey(PKC1_PK)
        val publicKey=keyConverter.toRSAPublicKey(PKC1_PBK)
        val text = "secret"

        val encrypted = rsaEcbOeapSha256AesGcmNoPadding.encrypt(publicKey, text.toByteArray())

        val decrypted = rsaEcbOeapSha256AesGcmNoPadding.decrypt(privateKey, encrypted)

        assertEquals(text, String(decrypted))
    }

    @Test
    fun convertFromPKCS1ToPCS8(){
        val keyConverter = KeyConverter()
        val privateKey = keyConverter.PKC1ToPKCS8PrivateKey(PKC1_PK) //under test
        val publicKey=keyConverter.toRSAPublicKey(PKCS8_PBK)
        val text = "secret"

        val encrypted = rsaEcbOeapSha256AesGcmNoPadding.encrypt(publicKey, text.toByteArray())

        val decrypted = rsaEcbOeapSha256AesGcmNoPadding.decrypt(privateKey, encrypted)

        assertEquals(text, String(decrypted))
    }

}