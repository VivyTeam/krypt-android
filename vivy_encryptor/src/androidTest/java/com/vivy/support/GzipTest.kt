package com.vivy.support

import android.util.Base64
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.not
import org.junit.Test

class GzipTest {

    @Test
    fun gzip() {
        val gzip = Gzip()
        val rawMessage = "Hello world!"

        val gzippedMessage = gzip.gzip(rawMessage.toByteArray())
        val gzippedMessageString = Base64.encodeToString(gzippedMessage, android.util.Base64.DEFAULT)
        assertThat(rawMessage, not(equalTo(gzippedMessageString)))

        val gunzippedMessage = gzip.gunzip(gzippedMessage)
        assertThat(String(gunzippedMessage), equalTo(rawMessage))
    }
}