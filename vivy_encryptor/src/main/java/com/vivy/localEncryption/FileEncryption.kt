package com.vivy.localEncryption

import com.google.common.base.Optional
import com.google.gson.GsonBuilder
import com.vivy.e2e.E2EEncryption
import com.vivy.e2e.EHREncryption
import com.vivy.support.EncryptionBase64
import com.vivy.support.Gzip
import com.vivy.support.KeyProvider
import io.reactivex.Single
import io.reactivex.functions.BiFunction
import timber.log.Timber
import java.security.PrivateKey
import java.security.PublicKey

class FileEncryption(private var keyProvider: KeyProvider) {

    private val GSON = GsonBuilder()
            .disableHtmlEscaping()
            .create()
    private val base64 = EncryptionBase64
    private val encryptor: E2EEncryption by lazy {
        EHREncryption()
    }
    private val gzip by lazy {
        Gzip()
    }
    fun decrypt(byteArray: ByteArray): Single<Optional<ByteArray>> {
        return  Single.just(String(byteArray))

                .map { base64.debase64(it)}
                .map { String(it) }
                .map { GSON.fromJson(it, E2EEncryption.Encrypted::class.java) }
                .zipWith(keyProvider.privateKey, BiFunction<E2EEncryption.Encrypted, PrivateKey,ByteArray> { encrypted, privateKey ->
                    encryptor.decrypt(privateKey, encrypted)
                })
                .map { gzip.gunzip(it) }
                .map { Optional.fromNullable(it) }
                .doOnError{ Timber.e(it)}
                .onErrorReturnItem(Optional.absent())

    }

    fun encrypt(byteArray: ByteArray): Single<ByteArray> {
        return Single.just(byteArray)
                .map { gzip.gzip(it) }
                .zipWith(keyProvider.publicKey, BiFunction<ByteArray, PublicKey, E2EEncryption.Encrypted> { bytes, pubKey->
                    encryptor.encrypt(pubKey, bytes)
                })
                .map { GSON.toJson(it) }
                .map { base64.base64(it.toByteArray()).toByteArray() }
                .doOnError{
                    Timber.d(it,"file encryption")
                }

    }
}