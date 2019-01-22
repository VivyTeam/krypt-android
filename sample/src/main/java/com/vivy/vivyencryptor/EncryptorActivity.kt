package com.vivy.vivyencryptor

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.vivy.e2e.E2EEncryption.Encrypted
import com.vivy.e2e.VivyEncryption
import com.vivy.support.EncryptionBase64
import io.reactivex.Observable
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.schedulers.Schedulers
import kotlinx.android.synthetic.main.activity_encryptor.decryptAction
import kotlinx.android.synthetic.main.activity_encryptor.decryptedText
import kotlinx.android.synthetic.main.activity_encryptor.encryptAction
import kotlinx.android.synthetic.main.activity_encryptor.encryptedText
import kotlinx.android.synthetic.main.activity_encryptor.planText
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import android.app.Activity
import android.content.Context
import android.view.View
import android.view.inputmethod.InputMethodManager
import androidx.core.content.ContextCompat.getSystemService



class EncryptorActivity : AppCompatActivity() {

    val compositeDisposable: CompositeDisposable = CompositeDisposable()

    private var testKey: KeyPair? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryptor)
        compositeDisposable.add(
            Observable.fromCallable {
                val keyGen = KeyPairGenerator.getInstance("RSA")
                keyGen.initialize(1024)
                return@fromCallable keyGen.generateKeyPair()
            }.subscribeOn(Schedulers.computation())
                .subscribeOn(AndroidSchedulers.mainThread())
                .subscribe {
                    this.testKey = it
                    initialiseUI()
                }
        )
    }

    @SuppressLint("SetTextI18n")
    private fun initialiseUI() {
        encryptAction.setOnClickListener {
            if (planText.text.isEmpty() || testKey == null) {
                return@setOnClickListener
            }

            encryptAndPrint(planText.text.toString(), testKey!!.public)
            decryptedText.text = ""

        }
        decryptAction.setOnClickListener {
            testKey?.let {decryptedText.text
                encrypted?.let {
                    compositeDisposable.add(
                        Observable
                            .just(it)
                            .map {
                                VivyEncryption().decrypt(testKey!!.private, it)
                            }.subscribeOn(Schedulers.computation())
                            .observeOn(AndroidSchedulers.mainThread()).subscribe {
                                decryptedText.text = "Decrypted Text: ${String(it)}"

                            }
                    )
                }
            }
        }
    }

    private var encrypted: Encrypted? = null

    private fun encryptAndPrint(
        text: String,
        publicKey: PublicKey
    ) {
        compositeDisposable.add(Observable.just(text.toByteArray())
            .map { VivyEncryption().encrypt(publicKey, it) }
            .subscribeOn(Schedulers.computation())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe {
                val output = StringBuilder()
                output.appendln("Encrypted payload base64: ${EncryptionBase64.base64(it.data)}\n")
                output.appendln("payload cipher keys encrypted using RSA : ${it.cipher} \n")
                encryptedText.text = output
                hideKeyboardFrom(this,encryptedText)
                encrypted = it
            })
    }

    fun hideKeyboardFrom(
        context: Context,
        view: View
    ) {
        val imm = context.getSystemService(Activity.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(view.windowToken, 0)
    }

}
