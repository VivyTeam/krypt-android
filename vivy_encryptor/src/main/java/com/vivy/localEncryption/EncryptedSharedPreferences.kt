package com.vivy.localEncryption

import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import java.util.*

interface EncryptedSharedPreferences {
    fun update(
            key: String,
            value: String,
            user: String
    ): Observable<String>

    fun update(
            key: String,
            value: String
    ): Observable<String>

    fun <J> update(
            key: String,
            value: J
    ): Observable<String>

    fun <J> update(
            key: String,
            value: J,
            user: String
    ): Observable<String>

    fun delete(
            key: String,
            user: String
    ): Completable

    fun delete(
            key: String
    ): Completable

    fun get(
            key: String,
            user: String
    ): Single<Optional<String>>

    fun get(
            key: String
    ): Single<Optional<String>>


    fun <J> get(
            key: String,
            clazz: Class<J>
    ): Single<Optional<J>>


    fun isEntryAvailable(
            key: String,
            user: String
    ): Single<Boolean>

    fun isEntryAvailable(
            key: String
    ): Single<Boolean>
}
