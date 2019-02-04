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
        ) .isEqualTo("sha256hpK5lcLpZoZ2AHIXUi4IgyRnwGCDqApocWM0DDc++zk=")
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
            .isEqualTo("sha256RonmY2BVOex5wlGRrLPkXn/MZV1Rhot4wRc9+cuK0zY=")
    }

}