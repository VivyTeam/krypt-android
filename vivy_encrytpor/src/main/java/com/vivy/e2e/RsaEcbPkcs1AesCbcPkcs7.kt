package com.vivy.e2e

import com.vivy.asymmetric.RsaEcbPkcs1
import com.vivy.symmetric.AesCbcPkcs7

class RsaEcbPkcs1AesCbcPkcs7 : AbstractAsymmetricSymmetricEncryption(RsaEcbPkcs1(), AesCbcPkcs7()) {

    override val version: String
        get() = VERSION

    companion object {

        val VERSION = "pkcscbc"
    }
}
