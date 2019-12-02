package com.vivy.support

import com.google.common.io.ByteStreams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

class Gzip {

    fun gzip(data: ByteArray): ByteArray {
        val outputStream = ByteArrayOutputStream()

        try {

            GZIPOutputStream(outputStream)
                    .use {

                        gzipOutputStream ->
                        ByteStreams.copy(ByteArrayInputStream(data), gzipOutputStream)
                    }
        } catch (ioe: IOException) {
            throw IllegalStateException("Failed to gzip data", ioe)
        }

        return outputStream.toByteArray()
    }

    fun gunzip(data: ByteArray): ByteArray {
        val outputStream = ByteArrayOutputStream(data.size)
        val inputStream = ByteArrayInputStream(data)
        try {
            GZIPInputStream(inputStream).use { gzipInputStream -> ByteStreams.copy(gzipInputStream, outputStream) }
        } catch (ioe: IOException) {
            throw IllegalStateException("Failed to gunzip data", ioe)
        }

        return outputStream.toByteArray()
    }
}
