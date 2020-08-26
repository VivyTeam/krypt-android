package com.vivy.asymmetric

import android.util.Base64.DEFAULT
import android.util.Base64.decode
import timber.log.Timber
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException

object RSASignatureValidator {

    fun verifyDigitalSignature(
        payload: String,
        signedPayload: String,
        publicKey: PublicKey
    ): Boolean {
        return try {
            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            signature.update(payload.toByteArray())

            val signedPayloadContent = decode(signedPayload, DEFAULT)

            signature.verify(signedPayloadContent)
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
