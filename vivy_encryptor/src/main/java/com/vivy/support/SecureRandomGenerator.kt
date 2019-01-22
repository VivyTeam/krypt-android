package com.vivy.support

import java.security.SecureRandom

class SecureRandomGenerator {

    fun string(len: Int): String {
        val rnd = SecureRandom()
        val sb = StringBuilder(len)
        for (i in 0 until len) {
            val nextLong = rnd.nextLong()
            // will be either 256 or 128 char depends on device architecture
            sb.append(java.lang.Long.toHexString(nextLong))
        }
        return sb.toString()
    }

    fun bytes(len: Int): ByteArray {
        val holder = ByteArray(len)
        SecureRandom().nextBytes(holder)
        return holder
    }
}
