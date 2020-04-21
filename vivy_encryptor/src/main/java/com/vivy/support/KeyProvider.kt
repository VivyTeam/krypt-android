package com.vivy.support

import io.reactivex.Single
import java.security.PrivateKey
import java.security.PublicKey

interface KeyProvider {
    fun getPrivateKey(): Single<PrivateKey>
    fun getPublicKey(): Single<PublicKey>
}
