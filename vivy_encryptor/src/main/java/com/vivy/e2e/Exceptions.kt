package com.vivy.e2e

class DecryptionFailed(val throwable: Throwable?) : Throwable(throwable)
class EncryptionFailed(val throwable: Throwable?) : Throwable(throwable)