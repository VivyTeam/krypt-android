package com.vivy.e2e

import com.google.gson.annotations.SerializedName
import java.security.PrivateKey
import java.security.PublicKey

interface E2EEncryption {

    val version: String

    fun encrypt(
        publicKey: PublicKey,
        plainData: ByteArray
    ): Encrypted

    fun decrypt(
        privateKey: PrivateKey,
        encrypted: Encrypted
    ): ByteArray

    data class Encrypted(
        @SerializedName("data") var data: ByteArray,
        @SerializedName("cipher") var cipher: String,
        @SerializedName("version") var version: String
    )

}
