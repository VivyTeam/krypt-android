package com.vivy.support;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.reactivex.Single;

public interface KeyProvider {
    public Single<PrivateKey> getPrivateKey();

    public Single<PublicKey> getPublicKey();
}
