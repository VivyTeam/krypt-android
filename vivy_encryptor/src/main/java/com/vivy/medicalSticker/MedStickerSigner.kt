package com.vivy.medicalSticker

import com.google.common.hash.Hashing
import com.vivy.support.EncryptionBase64
import java.io.ByteArrayOutputStream

internal object MedStickerSigner {

    fun accessSignature(medStickerCipherAttr: MedStickerCipherAttr,salt:ByteArray):String{
        return "sha256" + EncryptionBase64.base64(signBytes(medStickerCipherAttr.key,medStickerCipherAttr.iv,salt))
    }

    fun signBytes(key:ByteArray,iv:ByteArray,salt: ByteArray):ByteArray{
         ByteArrayOutputStream()
            .use {
                it.write(key)
                it.write(iv)
                it.write(salt)
                return Hashing.sha256()
                    .hashBytes(it.toByteArray())
                    .asBytes()
            }

    }
}