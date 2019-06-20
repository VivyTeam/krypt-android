package com.vivy.medicalSticker.v2.model

data class EncryptedEmergencySticker(
        val data: ByteArray,
        val fingerprintFile: ByteArray,
        val attr: EmergencyStickerCipherAttr
    )