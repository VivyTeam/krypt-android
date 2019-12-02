package com.vivy.medicalSticker.charlie.model

import com.vivy.medicalSticker.MedStickerCipherAttr

data class EncryptedEmergencySticker(
        val data: ByteArray,
        val fingerprintFile: String,
        val attr: MedStickerCipherAttr
)