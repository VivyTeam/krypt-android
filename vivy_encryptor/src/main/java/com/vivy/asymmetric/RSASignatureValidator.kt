package com.vivy.asymmetric

import timber.log.Timber
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException

object RSASignatureValidator {

    fun verifyDigitalSignature(
        payload: String,
        signedPayload: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            signature.update(payload.toByteArray())
            signature.verify(signedPayload)
        } catch (e: NoSuchAlgorithmException) {
            Timber.e(e)
            false
        } catch (e: InvalidKeyException) {
            Timber.e(e)
            false
        } catch (e: SignatureException) {
            Timber.e(e)
            false
        }
    }

}
