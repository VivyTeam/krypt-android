package com.vivy.medicalSticker

import org.assertj.core.api.Assertions
import org.junit.Test

class MedStickerSignerContractTest {

    internal val service = MedStickerSigner
    val encrypt = MedStickerEncryption
    @Test
    fun signTestAdam() {
        val pin = "qmHuG263"
        val code = "7i6XA2zz"
        val salt = "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
        val att=encrypt.deriveKey(code,pin,MedStickerCipherAttr.ADAM)

        Assertions.assertThat(
            service.accessSignature(att,salt.toByteArray())
        ) .isEqualTo("sha2566VMS5+x3CdtLE8gTzcGHcB29u6phH5IBEY7DKDHZv7w=")
    }

    @Test
    fun signTestBritney() {
        val pin = "qmHuG263"
        val code = "7i6XA2zz"
        val salt = "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
        val att=encrypt.deriveKey(code,pin,MedStickerCipherAttr.BRITNEY)

        Assertions.assertThat(
            service.accessSignature(att,salt.toByteArray())
        )
            .isEqualTo("sha256dmkV0L/hUFWkEEz0DnjvCCKfGAfLkfYv8ZaVuKZFP1w=")
    }

}