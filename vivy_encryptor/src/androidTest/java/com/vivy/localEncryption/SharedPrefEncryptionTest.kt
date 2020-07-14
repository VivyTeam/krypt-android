package com.vivy.localEncryption

import android.content.SharedPreferences
import android.preference.PreferenceManager
import androidx.test.platform.app.InstrumentationRegistry.getInstrumentation
import com.vivy.support.KeyProvider
import io.reactivex.Single
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey

class SharedPrefEncryptionTest {

    lateinit var encryptedSharedPrefUtil: EncryptedSharedPrefUtil

    val userIdentifier: UserIdentifier by lazy {
        object : UserIdentifier {
            override fun getId(): String {
                return "Mo@vivy.com"
            }
        }
    }

    lateinit var sharedPreferences: SharedPreferences
    @Before
    fun setup() {
        val instrumentation = getInstrumentation()
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(instrumentation.context)
        sharedPreferences.edit().clear().commit()
    }

    private fun generateRandomTestKey(): KeyProvider {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(1024)
        val smallKeypair = keyGen.generateKeyPair()
        return object : KeyProvider {
            override fun getPrivateKey(): Single<PrivateKey> {
                return Single.just(smallKeypair.private)
            }

            override fun getPublicKey(): Single<PublicKey> {
                return Single.just(smallKeypair.public)
            }
        }
    }

    @Test
    fun encryptDecrypt() {
        val keyProvider = generateRandomTestKey()

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, keyProvider, userIdentifier)

        val encrypted = "secret message"

        val encryptedMessage = encryptedSharedPrefUtil.encrypt(encrypted)
                .blockingFirst()
        val option = encryptedSharedPrefUtil.decrypt(encryptedMessage)
                .blockingGet()
        assertTrue(option.isPresent)
        val decryptedMessage = option.orElse("")
        assertEquals(encrypted, decryptedMessage)
    }


    @Test
    fun testGetForNonExistentValue() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val option =
                encryptedSharedPrefUtil.get("KEY_TEST_FOR_KEY_THAT_DOESN_T_EXIST").blockingGet()

        assertFalse(option.isPresent)
    }

    @Test
    fun testUpdateExistingValue() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val expectedResult = "expected test result!"

        encryptedSharedPrefUtil.update("KEY_TEST_FOR_KEY_THAT_EXISTS", expectedResult)
                .blockingFirst()

        val option = encryptedSharedPrefUtil.get("KEY_TEST_FOR_KEY_THAT_EXISTS").blockingGet()

        assertTrue(option.isPresent)
        assertEquals(expectedResult, option.get())
    }

    @Test
    fun testDeleteExistingValue() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val expectedResult = "expected test result!"
        val key = "KEY_TEST_FOR_KEY_THAT_EXISTS"
        encryptedSharedPrefUtil.update(key, expectedResult).blockingFirst()

        val option = encryptedSharedPrefUtil.get(key).blockingGet()

        assertTrue(option.isPresent)
        assertEquals(expectedResult, option.get())

        encryptedSharedPrefUtil.delete(key).blockingGet()

        assertFalse(encryptedSharedPrefUtil.get(key).blockingGet().isPresent)
    }


    @Test
    fun testGetForNonExistentValuePassingId() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val option = encryptedSharedPrefUtil.get(
                "KEY_TEST_FOR_KEY_THAT_DOESN_T_EXIST",
                userIdentifier.getId()
        ).blockingGet()

        assertFalse(option.isPresent)
    }

    @Test
    fun testUpdateExistingValuePassingId() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val expectedResult = "expected test result!"

        encryptedSharedPrefUtil.update("KEY_TEST_FOR_KEY_THAT_EXISTS", expectedResult)
                .blockingFirst()

        val option =
                encryptedSharedPrefUtil.get("KEY_TEST_FOR_KEY_THAT_EXISTS", userIdentifier.getId())
                        .blockingGet()

        assertTrue(option.isPresent)
        assertEquals(expectedResult, option.get())
    }

    @Test
    fun testDeleteExistingValuePassingId() {

        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)

        val expectedResult = "expected test result!"
        val key = "KEY_TEST_FOR_KEY_THAT_EXISTS"
        encryptedSharedPrefUtil.update(key, expectedResult, userIdentifier.getId()).blockingFirst()

        val option = encryptedSharedPrefUtil.get(key).blockingGet()

        assertTrue(option.isPresent)
        assertEquals(expectedResult, option.get())

        encryptedSharedPrefUtil.delete(key, userIdentifier.getId()).blockingGet()

        assertFalse(encryptedSharedPrefUtil.get(key).blockingGet().isPresent)
    }

    @Test
    fun testAvailabilityCheck() {
        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)
        val keyForExistingValue = "KEY_FOR_EXISTING_VALUE"
        val keyForNonExistingValue = "Key_FOR_MISSING_VALUE"
        val value = "VALUE"
        encryptedSharedPrefUtil.update(keyForExistingValue, value).blockingFirst()
        val returnedForExistingValue =
                encryptedSharedPrefUtil.isEntryAvailable(keyForExistingValue).blockingGet()
        val returnedForNonExistingValue =
                encryptedSharedPrefUtil.isEntryAvailable(keyForNonExistingValue).blockingGet()
        assertTrue(returnedForExistingValue)
        assertFalse(returnedForNonExistingValue)
    }

    @Test
    fun testGetWithObjects() {
        encryptedSharedPrefUtil =
                EncryptedSharedPrefUtil(sharedPreferences, generateRandomTestKey(), userIdentifier)
        val keyForObject = "KEY_FOR_OBJECT"
        val objectToSave = TestClass("TestString", 123)
        encryptedSharedPrefUtil.update(keyForObject, objectToSave).blockingFirst()
        val retrievedValue = encryptedSharedPrefUtil.get(keyForObject, TestClass::class.java).blockingGet().orElseGet { null }
        assertEquals(objectToSave, retrievedValue)
    }


    data class TestClass(val stringProperty: String, val IntegerProperty: Int)


}
