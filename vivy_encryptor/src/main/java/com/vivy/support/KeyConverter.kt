package com.vivy.support

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
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class KeyConverter {

    fun toPem(rsaPrivateKey: RSAPrivateKey): String {
        val privateKey = PemObject("PRIVATE KEY", rsaPrivateKey.encoded)

        val outputStream = ByteArrayOutputStream()
        try {
            PemWriter(OutputStreamWriter(outputStream)).use { pemWriter -> pemWriter.writeObject(privateKey) }
        } catch (e: IOException) {
            throw IllegalStateException(e)
        }

        return String(outputStream.toByteArray())
    }

    fun toPem(rsaPublicKey: RSAPublicKey): String {
        val publicKey = PemObject("PUBLIC KEY", rsaPublicKey.encoded)

        val outputStream = ByteArrayOutputStream()
        try {
            PemWriter(OutputStreamWriter(outputStream)).use { pemWriter -> pemWriter.writeObject(publicKey) }
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
        } catch (e: Exception){
            throw java.lang.IllegalStateException("Unable to convert public key ",e)
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
        } catch (e: Exception){
            throw java.lang.IllegalStateException("Unable to convert private key ",e)
        }

    }

    /*
    https://stackoverflow.com/a/41953072
    https://gist.github.com/markscottwright/4bd563fa91e9a72bf1ce12a0ff6567aa#gistcomment-2657458
   */
    fun PKC1ToPKCS8PrivateKey(privateKeyString: String): PrivateKey {
        try {
            val pemParser = PEMParser(StringReader(privateKeyString))
            val converter = JcaPEMKeyConverter()
            val `object` = pemParser.readObject()
            val kp = converter.getKeyPair(`object` as PEMKeyPair)
            return kp.private
        } catch (e: IOException) {
            throw IllegalStateException("unable to convert PKCS1 to PCKC8",e)
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
        return keyPem.contains("RSA")
    }
}
