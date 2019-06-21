package com.vivy.medicalSticker.v2.model

import com.vivy.medicalSticker.MedStickerCipherAttr

data class EncryptedEmergencySticker(
        val data: ByteArray,
        val fingerprintFile: ByteArray,
        val attr: MedStickerCipherAttr
    )