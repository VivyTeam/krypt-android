package com.vivy.support

import com.google.crypto.tink.subtle.EllipticCurves
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStreamWriter
import java.io.StringReader
import java.io.StringWriter
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class KeyConverter {

    fun toPem(rsaPrivateKey: RSAPrivateKey): String {
        return toPem(rsaPrivateKey.encoded, "PRIVATE KEY")
    }

    fun toPem(rsaPublicKey: RSAPublicKey): String {
        return toPem(rsaPublicKey.encoded, "PUBLIC KEY")
    }
    fun toPem(rsaPublicKey: ECPublicKey): String {
        return toPem(rsaPublicKey.encoded, "PUBLIC KEY")
    }

    fun toPem(rsaPublicKey: ECPrivateKey): String {
        return toPem(rsaPublicKey.encoded, "EC PRIVATE KEY")
    }

    fun toPem(privateKeyInfo: PrivateKeyInfo): String {
        return toPem(privateKeyInfo.encoded, "PRIVATE KEY")
    }

    fun toPem(encryptedPrivateKeyInfo: EncryptedPrivateKeyInfo): String {
        return toPem(encryptedPrivateKeyInfo.encoded, "ENCRYPTED PRIVATE KEY")
    }

    private fun toPem(bytes: ByteArray, type: String): String {
        val pem = PemObject(type, bytes)
        val outputStream = ByteArrayOutputStream()
        try {
            PemWriter(OutputStreamWriter(outputStream)).use { pemWriter -> pemWriter.writeObject(pem) }
        } catch (e: IOException) {
            throw IllegalStateException(e)
        }

        return String(outputStream.toByteArray())
    }

    fun toRSAPublicKey(publicKeyString: String): RSAPublicKey {
        try {
            val stringReader = StringReader(publicKeyString)
            val pemObject = PemReader(stringReader).readPemObject()
            val pemContent = pemObject.content
            val publicKeySpec = X509EncodedKeySpec(pemContent)
            val kf = KeyFactory.getInstance("RSA")
            return kf.generatePublic(publicKeySpec) as RSAPublicKey
        } catch (e: Exception) {
            throw java.lang.IllegalStateException("Unable to convert public key ", e)
        }
    }

    fun toRSAPrivateKey(privateKeyString: String): RSAPrivateKey {
        try {
            val stringReader = StringReader(privateKeyString)
            val pemObject = PemReader(stringReader).readPemObject()
            val pemContent = pemObject.content
            val privateKeySpec = PKCS8EncodedKeySpec(pemContent)
            val kf = KeyFactory.getInstance("RSA")
            return kf.generatePrivate(privateKeySpec) as RSAPrivateKey
        } catch (e: Exception) {
            throw java.lang.IllegalStateException("Unable to convert private key ", e)
        }
    }

    fun toECPublicKey(pem: String): ECPublicKey {
        val `in` = StringReader(pem)
        val reader = PemReader(`in`)
        val pemObject = reader.readPemObject()
        return EllipticCurves.getEcPublicKey(pemObject.content)
    }
    /*
    https://stackoverflow.com/a/41953072
    https://gist.github.com/markscottwright/4bd563fa91e9a72bf1ce12a0ff6567aa#gistcomment-2657458
   */
    fun PKC1ToPKCS8PrivateKey(privateKeyString: String): PrivateKey {
        try {
            val pemParser = PEMParser(StringReader(privateKeyString))
            val converter = JcaPEMKeyConverter()
            val obj = pemParser.readObject()
            val kp = converter.getKeyPair(obj as PEMKeyPair)
            return kp.private
        } catch (e: IOException) {
            throw IllegalStateException("unable to convert PKCS1 to PCKC8", e)
        }
    }

    fun convertPKCS8ToPEM(privateKeyPKCS8: ByteArray): String {
        try {
            val pemObject = PemObject("PRIVATE KEY", privateKeyPKCS8)
            val stringWriter = StringWriter()
            PemWriter(stringWriter)
                    .use {
                        it.writeObject(pemObject)
                        it.close()
                    }

            return stringWriter.toString()
        } catch (e: IOException) {
            throw IllegalStateException("unable to convert PKCS8 To PEM", e)
        }
    }

    fun isFromPKCS1(keyPem: String): Boolean {
        return keyPem.contains("BEGIN RSA PRIVATE KEY")
    }
}
