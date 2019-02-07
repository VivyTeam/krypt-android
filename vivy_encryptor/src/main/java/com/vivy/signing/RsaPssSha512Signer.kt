package com.vivy.signing

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec


class RsaPssSha512Signer : Signer {

    companion object {
        const val SIGNATURE_ALGORITHM = "SHA512withRSA/PSS"
        const val MESSAGE_DIGEST = "SHA-512"
        const val MASK_GENERATION_FUNCTION = "MGF1"
        const val SALT_LEN = 512 / 8
        const val TRAILER_FIELD_0xBC = 1
    }


    override fun sign(bytes: ByteArray, privateKey: PrivateKey): ByteArray {
        try {
            Security.addProvider(BouncyCastleProvider())
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature!!.setParameter(PSSParameterSpec(MESSAGE_DIGEST, MASK_GENERATION_FUNCTION, MGF1ParameterSpec.SHA512, SALT_LEN, TRAILER_FIELD_0xBC))
            signature.initSign(privateKey)
            signature.update(bytes)

            return signature.sign()

        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is InvalidAlgorithmParameterException,
                is InvalidKeyException,
                is SignatureException -> throw IllegalStateException(e)
                else -> throw e
            }

        }
    }
}