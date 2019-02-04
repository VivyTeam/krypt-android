# android-crypto-lib
library being used by Vivy android client to perform crypto operations

# How to use?

### EHR Encryption:
```kotlin
val publicKey: PublicKey = getMyPublicKey()

val toBeEncrypted: ByteArray = "secret message".toByteArray(Charsets.UTF_8)

val encrypted: E2EEncryption.Encrypted = EHREncryption().encrypt(publicKey, Gzip().gzip(toBeEncrypted))
```
### EHR Decryption:
```kotlin
val privateKey: PrivateKey = getMyPrivateKey()

val decrypted: ByteArray = EHREncryption().decrypt(privateKey, Gzip().gunzip(encrypted))

val plainText: String = String(decrypted, Charsets.UTF_8)//secret message
```
##### for medical sticker currently there are two versions, adam and britney, encryption always use the latest which is Britney, decryption has to supply version

### Medical Sticker key derivation:
```kotlin
 val keyAttr: MedStickerCipherAttr = MedStickerEncryption.deriveKey(code = "qmHuG263", pin = "7i6XA2zz", version = MedStickerCipherAttr.BRITNEY)
```

### Medical Sticker encryption/Decryption:

```kotlin
val encryptedMedSticker: EncryptedMedSticker = MedStickerEncryption.encrypt(code = "qmHuG263", pin = "7i6XA2zz", data = "secret message".toByteArray(Charsets.UTF_8))

val encryptedKeyAttr: MedStickerCipherAttr = encryptedMedSticker.attr

val encrypted = encryptedMedSticker.data

val decryptedMessage = MedStickerEncryption.decrypt(encryptedKeyAttr, encrypted)

val plainText = String(decryptedMessage, Charsets.UTF_8)//secret message
        
```
License
----
Code is Released under the [MIT](https://opensource.org/licenses/MIT) license 
