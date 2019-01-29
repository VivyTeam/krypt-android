package com.vivy.asymmetric

import java.security.PrivateKey
import java.security.PublicKey

interface AsymmetricEncryption {

    fun encryptText(
        publicKey: PublicKey,
        decryptedText: String
    ): String

    fun decryptText(
        privateKey: PrivateKey,
        base64AndEncryptedContent: String
    ): String
}
