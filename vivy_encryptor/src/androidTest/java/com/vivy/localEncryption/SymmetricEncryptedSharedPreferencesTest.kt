package com.vivy.localEncryption

import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.Gson
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class SymmetricEncryptedSharedPreferencesTest {

    private lateinit var storage: SymmetricEncryptedSharedPreferences
    private lateinit var encryptedSharedPreferences: EncryptedSharedPreferences

    private val testEmail = "test@vivy.com"
    private val gson = Gson()

    private val userIdentifier: UserIdentifier by lazy {
        object : UserIdentifier {
            override fun getId(): String {
                return "test@vivy.com"
            }
        }
    }

    @Before
    fun setup() {
        encryptedSharedPreferences = setupEncryptedSharedPreferences()
        storage = SymmetricEncryptedSharedPreferences(encryptedSharedPreferences, userIdentifier, gson)
    }

    //region update

    @Test
    fun updateKeyForCurrentUser() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = "This is a test for updating a key without explicitly specifying the user"
        val key = "KEY_TEST_UPDATE_FOR_CURRENT_USER"

        storage.update(key, expectedResult).blockingFirst()

        storage.getMaybe(key, testEmail).test()
            .assertValue {
                it == expectedResult
            }
    }

    @Test
    fun updateKeyForSpecificUser() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = "This is a test for updating a key for a user that was specified"
        val key = "KEY_TEST_UPDATE_FOR_SPECIFIED_USER"
        val specificTestEmail = "anna@vivy.com"

        storage.update(key, expectedResult, specificTestEmail).blockingFirst()

        storage.getMaybe(key, specificTestEmail)
            .test()
            .assertValue {
                it == expectedResult
            }

        storage.getMaybe(key, testEmail)
            .test()
            .assertResult()
    }

    @Test
    fun updateKeyForCurrentUserWithType() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = TestObject("This is a test for updating a key without explicitly specifying the user")
        val key = "KEY_TEST_UPDATE_FOR_CURRENT_USER_WITH_TYPE"

        storage.update(key, expectedResult).blockingFirst()

        storage.getMaybe(key, TestObject::class.java).test()
            .assertValue {
                it == expectedResult
            }
    }

    @Test
    fun updateKeyForSpecificUserWithType() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = TestObject("This is a test for updating a key for a specified user with type")
        val key = "KEY_TEST_UPDATE_FOR_SPECIFIED_USER_WITH_TYPE"
        val specificTestEmail = "anna@vivy.com"

        storage.update(key, expectedResult, specificTestEmail).blockingFirst()

        storage.getMaybe(key, specificTestEmail, TestObject::class.java).test()
            .assertValue {
                it == expectedResult
            }
    }

    //endregion update

    //region delete

    @Test
    fun deleteKeyForCurrentUser() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = "This is a test for deleting a key without explicitly specifying the user"
        val key = "KEY_TEST_DELETE_FOR_CURRENT_USER"

        storage.update(key, expectedResult).blockingFirst()
        storage.delete(key).blockingGet()

        storage.getMaybe(key, testEmail)
            .test()
            .assertResult()
    }

    @Test
    fun deleteKeyForSpecifiedUser() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = "This is a test for deleting a key for a specified user"
        val key = "KEY_TEST_DELETE_FOR_SPECIFIED_USER"
        val specificTestEmail = "anna@vivy.com"

        storage.update(key, expectedResult, specificTestEmail).blockingFirst()
        storage.delete(key, specificTestEmail).blockingGet()

        storage.getMaybe(key, specificTestEmail)
            .test()
            .assertResult()
    }
    //endregion delete

    //region available

    @Test
    fun isEntryAvailableForCurrentUserForExistingKey() {
        encryptedSharedPreferences.edit().clear()

        val value = "This is a test for checking for a key for the current user"
        val key = "KEY_TEST_EXISTING_KEY_FOR_CURRENT_USER"

        storage.update(key, value).blockingFirst()

        storage.isEntryAvailable(key, testEmail).test().assertValue(true)
    }

    @Test
    fun isEntryAvailableForCurrentUserForUnknownKey() {
        encryptedSharedPreferences.edit().clear()

        val key = "KEY_TEST_UNKNOWN_KEY_FOR_CURRENT_USER"

        storage.isEntryAvailable(key, testEmail).test().assertValue(false)
    }

    @Test
    fun isEntryAvailableForSpecificUserForExistingKey() {
        encryptedSharedPreferences.edit().clear()

        val value = "This is a test for checking for a key for a specified user"
        val key = "KEY_TEST_EXISTING_KEY_FOR_SPECIFIED_USER"
        val specificTestEmail = "anna@vivy.com"

        storage.update(key, value, specificTestEmail).blockingFirst()

        val result = storage.isEntryAvailable(key, specificTestEmail).blockingGet()

        Assert.assertEquals(result, true)
    }

    @Test
    fun isEntryAvailableForSpecificUserForUnknownKey() {
        encryptedSharedPreferences.edit().clear()

        val key = "KEY_TEST_UNKNOWN_KEY_FOR_SPECIFIED_USER"
        val specificTestEmail = "anna@vivy.com"

        val result = storage.isEntryAvailable(key, specificTestEmail).blockingGet()

        Assert.assertEquals(result, false)
    }

    //endregion available

    //region geMaybe

    @Test
    fun getKeyForCurrentUser() {
        encryptedSharedPreferences.edit().clear()

        val expectedResult = "This is a test for getting a key without explicitly specifying the user"
        val key = "KEY_TEST_GET_FOR_CURRENT_USER"

        storage.update(key, expectedResult).blockingFirst()

        storage.getMaybe(key)
            .test()
            .assertValue { it == expectedResult }
    }

    //endregion getMaybe

    private fun setupEncryptedSharedPreferences(): EncryptedSharedPreferences {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

        return EncryptedSharedPreferences.create(
            "TEST_STORAGE",
            masterKeyAlias,
            instrumentation.context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ) as EncryptedSharedPreferences
    }

    private data class TestObject(
        val test: String
    )
}