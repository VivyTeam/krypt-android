package com.vivy.support

import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.not
import org.junit.Test
import java.nio.charset.StandardCharsets

class Base64EncoderTest {

    internal var base64 = Base64Encoder

    @Test
    fun base64() {
        val targetString = "hello worlds!"

        val basedString = base64.base64(targetString.toByteArray(StandardCharsets.UTF_8))

        assertThat(targetString, not(equalTo(basedString)))

        val unBase64String = base64.debase64(basedString)

        assertThat(targetString, equalTo(String(unBase64String, StandardCharsets.UTF_8)))
    }
}