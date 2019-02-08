package com.vivy.medicalSticker

import com.vivy.support.Base64Encoder
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class MedStickerEncryptionContractTest {
    val service = MedStickerEncryption
    val encryptionBase64 = Base64Encoder

    @Test
    fun driveKeyAdamContractTest() {
        val keyAttr = service.deriveKey("7i6XA2zz", "qmHuG263", MedStickerCipherAttr.ADAM)

        assertThat(encryptionBase64.base64(keyAttr.key))
            .isEqualTo("Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=")

        assertThat(encryptionBase64.base64(keyAttr.iv))
            .isEqualTo("gi44bZGuBBdLpMISpeppWQ==")

    }

    @Test
    fun driveKeyBritneyContractTest() {
        val keyAttr = service.deriveKey("7i6XA2zz", "qmHuG263", MedStickerCipherAttr.BRITNEY)

        assertThat(encryptionBase64.base64(keyAttr.key))
            .isEqualTo("1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=")

        assertThat(encryptionBase64.base64(keyAttr.iv))
            .isEqualTo("aoiywBzTwYxzKQz45UxWaQ==")

    }

    @Test
    fun medStickerEncryptionAdam() {
        val encrypted = service.encrypt("7i6XA2zz", "qmHuG263", "A Healthier Life is a Happier Life".toByteArray(), MedStickerCipherAttr.ADAM)

        assertThat(encryptionBase64.base64(encrypted.data))
            .isEqualTo("rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw")

    }

    @Test
    fun medStickerDecryptionBritny() {
        val pin = "qmHuG263"
        val code = "7i6XA2zz"

        val encrypted = service.encrypt(code = code, pin = pin, data = "A Healthier Life is a Happier Life".toByteArray(), version = MedStickerCipherAttr.BRITNEY).data

        assertThat(encryptionBase64.base64(encrypted))
            .isEqualTo("1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q=")
    }


    @Test
    fun medStickerDecryptionBritney() {

        val key = encryptionBase64.debase64("1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=")
        val iv = encryptionBase64.debase64("aoiywBzTwYxzKQz45UxWaQ==")

        val encrypted = encryptionBase64.debase64(
            "1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q="
        )

        val decrypted = service.decrypt(MedStickerCipherAttr(key, iv, MedStickerCipherAttr.BRITNEY), encrypted)

        assertThat(String(decrypted))
            .isEqualTo("A Healthier Life is a Happier Life")

    }

    @Test
    fun medStickerDecryptionAdam() {
        val key = encryptionBase64.debase64("Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=")
        val iv = encryptionBase64.debase64("gi44bZGuBBdLpMISpeppWQ==")

        val encrypted = encryptionBase64.debase64(
            "rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw"
        )

        val decrypted = service.decrypt(MedStickerCipherAttr(key, iv, MedStickerCipherAttr.ADAM), encrypted)

        assertThat(String(decrypted))
            .isEqualTo("A Healthier Life is a Happier Life")

    }

}