package com.vivy

import com.google.crypto.tink.subtle.EllipticCurves
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter

import javax.crypto.KeyAgreement
import java.io.StringReader
import java.io.StringWriter
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.util.Base64
import org.junit.Test

internal class ECDHTest {

    @Test
    fun keyExchange() {
        val clientKeyPair = createKeyPair("Client")
        val myPublicKey = encodePublicKey(clientKeyPair.public)

        val serverPubKey = callServer(myPublicKey)
        val serverPublicKey = parseKey(serverPubKey)

        // Perform key agreement
        val sharedSecret = calculateSecret(serverPublicKey, clientKeyPair.private)
        println("Client stores secret: \n" + Base64.getEncoder().encodeToString(sharedSecret))
    }

    private fun callServer(clientPubKey: String): String {
        val clientPublicKey = parseKey(clientPubKey)

        val serverKeyPair = createKeyPair("Server")
        val secret = calculateSecret(clientPublicKey, serverKeyPair.private)
        println("Server stores secret: \n" + Base64.getEncoder().encodeToString(secret))

        return encodePublicKey(serverKeyPair.public)
    }

    private fun calculateSecret(
        clientPublicKey: PublicKey,
        privateKey: PrivateKey
    ): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(clientPublicKey, true)
        return ka.generateSecret()
    }

    private fun parseKey(pem: String): PublicKey {
        return decode(pem)
    }

    private fun createKeyPair(name: String): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(EllipticCurves.getNistP256Params())
        val keyPair = kpg.generateKeyPair()
        return keyPair
    }

    companion object {

        fun decode(pem: String): ECPublicKey {
            val `in` = StringReader(pem)
            val reader = PemReader(`in`)
            val pemObject = reader.readPemObject()
            return EllipticCurves.getEcPublicKey(pemObject.content)
        }

        fun encodePublicKey(publicKey: PublicKey): String {
            val out = StringWriter()
            val writer = PemWriter(out)
            writer.writeObject(PemObject("PUBLIC KEY", publicKey.encoded))
            writer.flush()
            return out.toString()
        }

        fun encodePrivateKey(privateKey: PrivateKey): String {
            val out = StringWriter()
            val writer = PemWriter(out)
            writer.writeObject(PemObject("EC PRIVATE KEY", privateKey.encoded))
            writer.flush()
            return out.toString()
        }
    }
}
