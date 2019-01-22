package com.vivy.vivyencryptor

import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.IdlingRegistry
import androidx.test.espresso.action.ViewActions.clearText
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.typeText
import androidx.test.espresso.assertion.ViewAssertions
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.idling.CountingIdlingResource
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.rule.ActivityTestRule
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class EncryptSampleActivityTest {

    @JvmField @Rule val activity: ActivityTestRule<EncryptSampleActivity> = ActivityTestRule(EncryptSampleActivity::class.java, true, false)

    @Before
    fun setup() {
        IdlingRegistry.getInstance().register(EncryptSampleActivity.countingIdlingResource)

    }

    @After
    fun tearDown() {
        IdlingRegistry.getInstance().unregister(EncryptSampleActivity.countingIdlingResource)
    }

    @Test
    fun validateEncryptionFunctionalityWorks() {

        activity.launchActivity(null)
        //encrypt
        onView(withId(R.id.planText))
            .perform(clearText(), typeText("secret stuff"))
        onView(withId(R.id.encryptAction)).perform(click())


        onView(withId(R.id.encryptedText))
            .check(ViewAssertions.matches(isDisplayed()))
            .check(ViewAssertions.matches(not(withText(""))))


        //decrypt
        onView(withId(R.id.decryptedText)).check(matches(withText("")))

        onView(withId(R.id.decryptAction)).perform(click())

        onView(withId(R.id.decryptedText)).check(matches(withText("Decrypted Text: secret stuff")))

    }
}