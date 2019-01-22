package com.vivy.support;

import io.reactivex.Single;
import java.security.PrivateKey;

import io.reactivex.Observable;
import java.security.PublicKey;

public interface KeyProvider {
    public Single<PrivateKey> getPrivateKey();
    public Single<PublicKey> getPublicKey();
}
