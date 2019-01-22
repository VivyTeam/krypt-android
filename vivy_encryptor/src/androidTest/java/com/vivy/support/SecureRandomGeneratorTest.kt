package com.vivy.support

import org.hamcrest.Matchers
import org.hamcrest.Matchers.`is`
import org.junit.Assert.assertThat
import org.junit.Test

class SecureRandomGeneratorTest {

    private val service = SecureRandomGenerator()

    @Test
    fun string() {
        val random = service.string(16)
        assertThat(random, `is`(Matchers.not(service.string(16))))
    }

    @Test
    fun bytes() {
        val random = service.bytes(16)
        assertThat(random, `is`(Matchers.not(service.bytes(16))))
    }
}