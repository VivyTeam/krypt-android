package com.vivy.medicalSticker

data class MedStickerKey(
    val key: ByteArray,
    val iv: ByteArray,
    val version: String = BRITNEY
) {
    companion object {
        const val ADAM = "adam"
        const val BRITNEY = "britney"
    }
}