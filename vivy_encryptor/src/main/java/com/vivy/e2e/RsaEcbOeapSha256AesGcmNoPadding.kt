package com.vivy.e2e

import com.vivy.asymmetric.RsaEcbOeapSha256
import com.vivy.symmetric.AesGcmNoPadding

class RsaEcbOeapSha256AesGcmNoPadding : AbstractAsymmetricSymmetricEncryption(RsaEcbOeapSha256(), AesGcmNoPadding()) {

    override val version: String
        get() = VERSION

    companion object {

        val VERSION = "oeapgcm"
    }
}
