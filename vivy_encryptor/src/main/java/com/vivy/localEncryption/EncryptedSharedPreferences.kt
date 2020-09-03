package com.vivy.localEncryption

import io.reactivex.Completable
import io.reactivex.Maybe
import io.reactivex.Observable
import io.reactivex.Single

interface EncryptedSharedPreferences {

    //region update
    fun update(
        key: String,
        value: String
    ): Observable<String>

    fun update(
        key: String,
        value: String,
        user: String
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

    //endregion update

    //region delete
    fun delete(
        key: String
    ): Completable

    fun delete(
        key: String,
        user: String
    ): Completable
    //endregion delete

    //region get deprecated
    @Deprecated("use @getMaybe instead", ReplaceWith("getMaybe(key)"))
    fun get(
        key: String
    ): Single<com.google.common.base.Optional<String>> {
        return Single.just(com.google.common.base.Optional.absent())
    }

    @Deprecated("use @getMaybe instead", ReplaceWith("getMaybe(key, user)"))
    fun get(
        key: String,
        user: String
    ): Single<com.google.common.base.Optional<String>> {
        return Single.just(com.google.common.base.Optional.absent())
    }

    @Deprecated("use @getMaybe instead", ReplaceWith("getMaybe(key, clazz)"))
    fun <J> get(
        key: String,
        clazz: Class<J>
    ): Single<polanski.option.Option<J>> {
        return Single.just(polanski.option.Option.none())
    }
    //endregion get

    //region getMaybe
    fun getMaybe(
        key: String
    ): Maybe<String> {
        return Maybe.empty()
    }

    fun getMaybe(
        key: String,
        user: String
    ): Maybe<String> {
        return Maybe.empty()
    }

    fun <J> getMaybe(
        key: String,
        clazz: Class<J>
    ): Maybe<J> {
        return Maybe.empty()
    }

    fun <J> getMaybe(
        key: String,
        user: String,
        clazz: Class<J>
    ): Maybe<J> {
        return Maybe.empty()
    }
    //endregion getMaybe

    //region available
    fun isEntryAvailable(
        key: String,
        user: String
    ): Single<Boolean>

    fun isEntryAvailable(
        key: String
    ): Single<Boolean>
    //endregion available

}