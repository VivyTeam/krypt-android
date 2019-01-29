package com.vivy.support

import java.security.KeyPair
import java.security.KeyPairGenerator

object KeyGenerator {

    fun generateKeyPair(keySize: Int = 1024): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(keySize)
        return keyGen.generateKeyPair()!!
    }
}