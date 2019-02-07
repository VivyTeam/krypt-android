package com.vivy.signing

import java.security.PrivateKey


interface Signer {
    fun sign(bytes: ByteArray, privateKey: PrivateKey): ByteArray
}