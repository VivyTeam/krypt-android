package com.vivy.medicalSticker

import org.assertj.core.api.Assertions
import org.junit.Test

class MedStickerSignerContractTest {

    internal val service = MedStickerSigner
    val encrypt = MedStickerEncryption
    @Test
    fun signTestAdam() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val salt = "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
        val att=encrypt.deriveKey(code,pin,MedStickerCipherAttr.ADAM)

        Assertions.assertThat(
            service.accessSignature(att,salt.toByteArray())
        ) .isEqualTo("sha256wi5J6zNjkH2clai0Ygfh375AJbWcOURR4HJlIxht2wo=")
    }

    @Test
    fun signTestBritney() {
        val pin = "yzuygF6M"
        val code = "yeeXCYff"
        val salt = "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
        val att=encrypt.deriveKey(code,pin,MedStickerCipherAttr.BRITNEY)

        Assertions.assertThat(
            service.accessSignature(att,salt.toByteArray())
        )
            .isEqualTo("sha256FkZmKpxsOivCB1MzfDNq2J8EAfzEhyapfn3gpQfuDgY=")
    }

}