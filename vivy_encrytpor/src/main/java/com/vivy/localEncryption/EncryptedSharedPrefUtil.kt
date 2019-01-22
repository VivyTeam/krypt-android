package com.vivy.localEncryption

import android.content.SharedPreferences
import com.google.common.base.Optional
import com.google.gson.GsonBuilder
import com.vivy.e2e.E2EEncryption.Encrypted
import com.vivy.e2e.VivyEncryption
import com.vivy.support.EncryptionBase64
import com.vivy.support.KeyProvider
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.functions.BiFunction
import polanski.option.Option
import timber.log.Timber
import java.security.PrivateKey
import java.security.PublicKey

open class EncryptedSharedPrefUtil(
    private val sharedPreferences: SharedPreferences,
    private val keyProvider: KeyProvider,
    private val userIdentifier: UserIdentifier
) {
    private val GSON = GsonBuilder()
        .disableHtmlEscaping()
        .create()
    internal val base64 = EncryptionBase64
    private val encrypt: VivyEncryption by lazy {
                VivyEncryption()
    }

    fun update(
        key: String,
        value: String,
        user: String = userIdentifier.getId()
    ): Observable<String> {
        return Observable.just(value)
            .switchMap { encrypt(it) }
            .map { encrypted ->
                sharedPreferences.edit().putString(key + user, encrypted).apply()
                value
            }

    }

    fun delete(
        key: String,
        user: String = userIdentifier.getId()
    ): Completable {
        return Completable.fromAction {
            sharedPreferences.edit().remove(key + user).apply()
        }
    }

     fun get(
        key: String,
        user: String = userIdentifier.getId()
    ): Single<Optional<String>> {
        return Single.defer {

            val encrypted = sharedPreferences.getString(key + user, null)
            encrypted?.let {

                decrypt(it)
            } ?:
                Single.just(Optional.absent())
        }
    }

    fun <J> get(
        key: String,
        clazz: Class<J>
    ): Single<Option<J>> {
        return get(key)
            .filter { it.isPresent }
            .map { it.or("") }
            .map { Option.tryAsOption<J> { GSON.fromJson(it, clazz) } }
            .onErrorReturn { Option.none() }
            .toSingle(Option.none())

    }

    fun decrypt(encryptedText: String): Single<Optional<String>> {
        return Single.just(encryptedText)
            .map { base64.debase64(it) }
            .map { String(it) }
            .map {
                GSON.fromJson(it, Encrypted::class.java) }
            .zipWith(keyProvider.privateKey, BiFunction<Encrypted, PrivateKey, ByteArray> { encrypted, privateKey -> encrypt.decrypt(privateKey, encrypted) })
            .map { Optional.fromNullable(String(it)) }
            .onErrorReturnItem(Optional.absent())
            .doOnError { Timber.d(it) }

    }

    fun encrypt(planText: String): Observable<String> {
        return Observable.just(planText)
            .map { it.toByteArray() }
            .zipWith(keyProvider.publicKey.toObservable(), BiFunction<ByteArray, PublicKey, Encrypted> { bytes, pubKey ->
                encrypt.encrypt(pubKey, bytes)
            })
            .map { GSON.toJson(it) }
            .map { base64.base64(it.toByteArray()) }
            .doOnError {
                Timber.d(it, "encrypted shared preference")
            }

    }

}
