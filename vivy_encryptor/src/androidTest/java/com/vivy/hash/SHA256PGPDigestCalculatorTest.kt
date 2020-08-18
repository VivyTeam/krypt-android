package com.vivy.hash

import org.junit.Assert
import org.junit.Test

class SHA256PGPDigestCalculatorTest {

    private val hashCalculator = SHA256PGPDigestCalculator()

    @Test
    fun getHashForStringReturnsExpectedOutput() {
        val text = "This text is supposed to get hashed"
        val expectedResult = byteArrayOf(
            67, 59, -86, 115, -80, 16, -85, -52, -29, -15, 16, -118, -76, -25, -9, -52, 114, -15, 96, 86, 77, -108, 54, -32, 90, -111, 8, 118, -79, 59, -10,
            -84
        )

        val result = hashCalculator.getHash(text)

        Assert.assertArrayEquals(expectedResult, result)
    }

    @Test
    fun getHashForByteArrayReturnsExpectedOutput() {
        val text = byteArrayOf(
            84, 104, 105, 115, 32, 116, 101, 120, 116, 32, 105, 115, 32, 115, 117, 112, 112, 111, 115, 101, 100, 32, 116, 111, 32, 103, 101, 116, 32, 104, 97,
            115, 104, 101, 100
        )
        val expectedResult = byteArrayOf(
            67, 59, -86, 115, -80, 16, -85, -52, -29, -15, 16, -118, -76, -25, -9, -52, 114, -15, 96, 86, 77, -108, 54, -32, 90, -111, 8, 118, -79, 59, -10,
            -84
        )
        val result = hashCalculator.getHash(text)

        Assert.assertArrayEquals(expectedResult, result)
    }

}