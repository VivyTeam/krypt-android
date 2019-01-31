package com.vivy.medicalSticker

import com.google.common.hash.Hashing
import com.vivy.support.EncryptionBase64
import java.io.ByteArrayOutputStream

internal object MedStickerSigner {

    fun accessSignature(medStickerKey: MedStickerKey,salt:ByteArray):String{
        return "sha256" + EncryptionBase64.base64(signBytes(medStickerKey.key,medStickerKey.iv,salt))
    }

    fun signBytes(key:ByteArray,iv:ByteArray,salt: ByteArray):ByteArray{
         ByteArrayOutputStream()
            .use {
                it.write(salt)
                it.write(key)
                it.write(iv)
                return Hashing.sha256()
                    .hashBytes(it.toByteArray())
                    .asBytes()
            }

    }
}