package com.vivy.hash

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.jcajce.io.OutputStreamFactory
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

class SHA256PGPDigestCalculator : PGPDigestCalculator {

    private var digest: MessageDigest

    init {
        try {
            digest = MessageDigest.getInstance("SHA-256")
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("cannot find SHA-256: " + e.message)
        }
    }

    override fun getAlgorithm(): Int {
        return HashAlgorithmTags.SHA256
    }

    override fun getOutputStream(): OutputStream {
        return OutputStreamFactory.createStream(digest)
    }

    override fun getDigest(): ByteArray {
        return digest.digest()
    }

    override fun reset() {
        digest.reset()
    }

    fun getHash(text: String): ByteArray {
        return getHash(text.toByteArray(StandardCharsets.UTF_8))
    }

    fun getHash(bytes: ByteArray): ByteArray {
        val hash = digest.digest(bytes)
        digest.reset()
        return hash
    }

}
