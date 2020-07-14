package com.vivy.localEncryption

import androidx.security.crypto.EncryptedSharedPreferences
import com.google.gson.Gson
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import java.util.*
import com.vivy.localEncryption.EncryptedSharedPreferences as VivyEncryptedSharedPreferences

@Suppress("TooManyFunctions")
class SymmetricEncryptedSharedPreferences(
    private val storage: EncryptedSharedPreferences,
    private val userIdentifier: UserIdentifier,
    private val gson: Gson
) : VivyEncryptedSharedPreferences {

    override fun update(key: String, value: String): Observable<String> {
        return update(key, value, userIdentifier.getId())
    }

    override fun <J> update(key: String, value: J): Observable<String> {
        return update(key, value, userIdentifier.getId())
    }

    override fun delete(key: String): Completable {
        return delete(key, userIdentifier.getId())
    }

    override fun get(key: String): Single<Optional<String>> {
        return get(key, userIdentifier.getId())
    }

    override fun isEntryAvailable(key: String): Single<Boolean> {
        return isEntryAvailable(key, userIdentifier.getId())
    }


    override fun update(key: String, value: String, user: String): Observable<String> {
        return Observable.fromCallable {
            storage.edit().putString(key + user, value).commit()
        }.map { value }
    }

    override fun <J> update(key: String, value: J, user: String): Observable<String> {
        return update(key, gson.toJson(value), user)
    }

    override fun delete(key: String, user: String): Completable {
        return Completable.fromCallable {
            storage.edit().remove(key + user).commit()
        }
    }

    override fun get(key: String, user: String): Single<Optional<String>> {
        return isEntryAvailable(key, user)
            .map { available ->
                if (!available) {
                    Optional.empty()
                } else {
                    val value = storage.getString(key + user, "") ?: ""
                    Optional.of(value)
                }
            }
    }

    override fun <J> get(key: String, clazz: Class<J>): Single<Optional<J>> {
        return get(key, userIdentifier.getId())
            .map {
                if (it.isPresent) {
                    Optional.of(gson.fromJson(it.get(), clazz))
                } else {
                    Optional.empty()
                }
            }
    }

    override fun isEntryAvailable(key: String, user: String): Single<Boolean> {
        return Single.fromCallable {
            storage.contains(key + user)
        }
    }

}
