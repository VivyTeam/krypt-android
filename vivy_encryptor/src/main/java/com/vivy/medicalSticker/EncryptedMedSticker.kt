package com.vivy.medicalSticker

data class EncryptedMedSticker(
  val data: ByteArray,
  val attr:MedStickerCipherAttr
)