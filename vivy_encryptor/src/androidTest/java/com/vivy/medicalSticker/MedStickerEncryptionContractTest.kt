package com.vivy.medicalSticker

import com.vivy.support.EncryptionBase64
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class MedStickerEncryptionContractTest {
    val service = MedStickerEncryption
    val encryptionBase64 = EncryptionBase64

    @Test
    fun driveKeyAdamContractTest() {
        val keyAttr = service.deriveKey("yeeXCYff", "yzuygF6M", MedStickerCipherAttr.ADAM)

        assertThat(encryptionBase64.base64(keyAttr.key))
            .isEqualTo("8soJNVPExZ7e9Jh09WQGosdzJ+i0HJ6fDt+yMbp2CsM=")

        assertThat(encryptionBase64.base64(keyAttr.iv))
            .isEqualTo("Mh5ZVDlef1mpllNsksXucg==")

    }

    @Test
    fun driveKeyBritneyContractTest() {
        val keyAttr = service.deriveKey("yeeXCYff", "yzuygF6M", MedStickerCipherAttr.BRITNEY)

        assertThat(encryptionBase64.base64(keyAttr.key))
            .isEqualTo("EdSOjdfxPyfeLm19guHEVmREhnJ1ekxzRSQjkLTuQ6w=")

        assertThat(encryptionBase64.base64(keyAttr.iv))
            .isEqualTo("4G7mC88WuqFt/zpceuHUFQ==")

    }

    @Test
    fun medStickerEncryptionAdam() {
        val encrypted = service.encrypt("yeeXCYff", "yzuygF6M", "secret".toByteArray(), MedStickerCipherAttr.ADAM)

        assertThat(encryptionBase64.base64(encrypted.data))
            .isEqualTo("0hP92D9TSOMdr3yXnOLGQdWUVGMuUGZ+jxdOg4wE1R8=")

    }

    @Test
    fun medStickerDecryptionBritney() {

        val key = encryptionBase64.debase64("EdSOjdfxPyfeLm19guHEVmREhnJ1ekxzRSQjkLTuQ6w=")
        val iv = encryptionBase64.debase64("4G7mC88WuqFt/zpceuHUFQ==")
        val encrypted = encryptionBase64.debase64(
            "RrrWVUp6/A7EeGT0b1xa2UoHiVp6b66fd7U57fvMnI7nIxR/nGCVcipTDVQciOPiMlOTeI78SfVKC+84Sx/Dd0Ea0Tl9amIfKRTYqDuUyLaSLaytJuNPvtSJr3PWJt8oDybbD5t1o5A3YNuD8oRi2mgxoo/o"
        )

        val decrypted = service.decrypt(MedStickerCipherAttr(key, iv, MedStickerCipherAttr.BRITNEY), encrypted)

        assertThat(String(decrypted))
            .isEqualTo("“Debugging” is like being the detective in a crime drama where you are also the murderer.")

    }

    @Test
    fun medStickerDecryptionAdam() {
        val key = encryptionBase64.debase64("8soJNVPExZ7e9Jh09WQGosdzJ+i0HJ6fDt+yMbp2CsM=")
        val iv = encryptionBase64.debase64("Mh5ZVDlef1mpllNsksXucg==")
        val encrypted = encryptionBase64.debase64(
            "TnjEXNfrBZJmNhCng+sLr22gPjqQMYPqv62Rgl9CAaNqPeHPubuP6cy53eweAkRJk+O7e4yFVvSC3FMa5Ylz86Ozkd2zoFX/ChVfC0BYaclxVDAijDq4LbKzDwp0QVVXiSTwoFLKOpFeFqrehr6q5g=="
        )

        val decrypted = service.decrypt(MedStickerCipherAttr(key, iv, MedStickerCipherAttr.ADAM), encrypted)

        assertThat(String(decrypted))
            .isEqualTo("“Debugging” is like being the detective in a crime drama where you are also the murderer.")


    }

}