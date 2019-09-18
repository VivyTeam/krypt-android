package com.vivy.localEncryption

import android.content.SharedPreferences
import com.google.common.annotations.VisibleForTesting
import com.google.common.base.Optional
import com.google.gson.GsonBuilder
import com.vivy.e2e.E2EEncryption.Encrypted
import com.vivy.e2e.EHREncryption
import com.vivy.support.Base64Encoder
import com.vivy.support.Gzip
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
) : EncryptedSharedPreferences {
    private val GSON = GsonBuilder()
        .disableHtmlEscaping()
        .create()
    private val gzip = Gzip()
    private val base64 = Base64Encoder
    private val encrypt: EHREncryption by lazy {
        EHREncryption()
    }


    override fun update(
        key: String,
        value: String,
        user: String
    ): Observable<String> {
        return Observable.just(value)
            .switchMap { encrypt(it) }
            .map { encrypted ->
                sharedPreferences.edit().putString(key + user, encrypted).apply()
                value
            }

    }

    override fun delete(
        key: String,
        user: String
    ): Completable {
        return Completable.fromAction {
            sharedPreferences.edit().remove(key + user).apply()
        }
    }

    override fun get(
        key: String,
        user: String
    ): Single<Optional<String>> {
        return Single.defer {

            val encrypted = sharedPreferences.getString(key + user, null)
            encrypted?.let {

                decrypt(it)
            } ?: Single.just(Optional.absent())
        }
    }

    override fun <J> get(
        key: String,
        clazz: Class<J>
    ): Single<Option<J>> {
        return get(key, userIdentifier.getId())
            .filter { it.isPresent }
            .map { it.or("") }
            .map { Option.tryAsOption<J> { GSON.fromJson(it, clazz) } }
            .onErrorReturn { Option.none() }
            .toSingle(Option.none())

    }

    override fun update(key: String, value: String): Observable<String> {
        return update(key, value, userIdentifier.getId())
    }

    override fun delete(key: String): Completable {
        return delete(key, userIdentifier.getId())
    }

    override fun get(key: String): Single<Optional<String>> {
        return get(key, userIdentifier.getId())
    }
    

    fun decrypt(encryptedText: String): Single<Optional<String>> {
        return Single.just(encryptedText)
            .map { base64.debase64(it) }
            .map { String(it) }
            .map {
                GSON.fromJson(it, Encrypted::class.java)
            }
            .zipWith(
                keyProvider.privateKey,
                BiFunction<Encrypted, PrivateKey, ByteArray> { encrypted, privateKey ->
                    encrypt.decrypt(
                        privateKey,
                        encrypted
                    )
                })
            .map { gzip.gunzip(it) }
            .map { Optional.fromNullable(String(it)) }
            .onErrorReturnItem(Optional.absent())
            .doOnError { Timber.d(it) }

    }

    fun encrypt(plainText: String): Observable<String> {
        return Observable.just(plainText)
            .map { it.toByteArray() }
            .map { gzip.gzip(it) }
            .zipWith(
                keyProvider.publicKey.toObservable(),
                BiFunction<ByteArray, PublicKey, Encrypted> { bytes, pubKey ->
                    encrypt.encrypt(pubKey, bytes)
                })
            .map { GSON.toJson(it) }
            .map { base64.base64(it.toByteArray()) }
            .doOnError {
                Timber.d(it, "encrypted shared preference")
            }

    }

}
