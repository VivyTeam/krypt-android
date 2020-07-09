package com.vivy.localEncryption

import androidx.security.crypto.EncryptedSharedPreferences
import com.google.gson.Gson
import io.reactivex.Completable
import io.reactivex.Maybe
import io.reactivex.Observable
import io.reactivex.Single
import com.vivy.localEncryption.EncryptedSharedPreferences as VivyEncryptedSharedPreferences

class SymmetricEncryptedSharedPreferences(
    private val storage: EncryptedSharedPreferences,
    private val userIdentifier: UserIdentifier,
    private val gson: Gson
) : VivyEncryptedSharedPreferences {

    //region update
    override fun update(
        key: String,
        value: String
    ): Observable<String> {
        return update(key, value, userIdentifier.getId())
    }

    override fun update(
        key: String,
        value: String,
        user: String
    ): Observable<String> {
        return Observable.fromCallable {
            storage.edit().putString(key + user, value).commit()
        }.map { value }
    }

    override fun <J> update(
        key: String,
        value: J
    ): Observable<String> {
        return update(key, value, userIdentifier.getId())
    }

    override fun <J> update(
        key: String,
        value: J,
        user: String
    ): Observable<String> {
        return update(key, gson.toJson(value), user)
    }
    //endregion update

    //region delete
    override fun delete(key: String): Completable {
        return delete(key, userIdentifier.getId())
    }

    override fun delete(
        key: String,
        user: String
    ): Completable {
        return Completable.fromCallable {
            storage.edit().remove(key + user).commit()
        }
    }
    //endregion delete

    //region getMaybe
    override fun getMaybe(
        key: String
    ): Maybe<String> {
        return getMaybe(key, userIdentifier.getId())
    }

    override fun getMaybe(
        key: String,
        user: String
    ): Maybe<String> {
        return isEntryAvailable(key, user)
            .flatMapMaybe { available ->
                if (!available) {
                    Maybe.empty()
                } else {
                    val value = storage.getString(key + user, "") ?: ""
                    Maybe.just(value)
                }
            }
    }

    override fun <J> getMaybe(
        key: String,
        clazz: Class<J>
    ): Maybe<J> {
        return getMaybe(key, userIdentifier.getId(), clazz)
    }

    override fun <J> getMaybe(
        key: String,
        user: String,
        clazz: Class<J>
    ): Maybe<J> {
        return getMaybe(key, user)
            .map {
                val value = gson.fromJson(it, clazz)
                value
            }
    }
    //endregion getMaybe

    //region available
    override fun isEntryAvailable(
        key: String
    ): Single<Boolean> {
        return isEntryAvailable(key, userIdentifier.getId())
    }

    override fun isEntryAvailable(
        key: String,
        user: String
    ): Single<Boolean> {
        return Single.fromCallable {
            storage.contains(key + user)
        }
    }
    //endregion available

}
