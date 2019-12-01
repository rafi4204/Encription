package com.example.encription

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_main.*
import androidx.core.content.ContextCompat.getSystemService
import android.icu.lang.UCharacter.GraphemeClusterBreak.T
import java.io.IOException
import java.security.*
import javax.crypto.*
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import androidx.core.app.ComponentActivity.ExtraData
import androidx.core.content.ContextCompat.getSystemService
import android.icu.lang.UCharacter.GraphemeClusterBreak.T
import android.util.Base64
import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.security.auth.x500.X500Principal


class MainActivity : AppCompatActivity() {
    var cipher: Cipher
    var keyStore: KeyStore

    init {
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        keyStore = createAndroidKeyStore()

    }
    companion object {
        val MASTER_KEY = "MASTER_KEY"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val input = et.text.toString()
        tv1.text=encrypt(input,"")
        tv2.text=decrypt(tv1.text.toString(),"")



    }

    fun getAndroidKeyStoreAsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(alias)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }


    fun encrypt(data: String, keyPassword: String? = null): String {
        val masterKey = getAndroidKeyStoreAsymmetricKeyPair(MASTER_KEY)
        return encrypt(data, masterKey?.public)
    }

    fun decrypt(data: String, keyPassword: String? = null): String {
        val masterKey = getAndroidKeyStoreAsymmetricKeyPair(MASTER_KEY)
        return decrypt(data, masterKey?.private)
    }



    fun encrypt(data: String, key: Key?): String {
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(bytes, Base64.DEFAULT)
    }

    fun decrypt(data: String, key: Key?): String {
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedData = Base64.decode(data, Base64.DEFAULT)
        val decodedData = cipher.doFinal(encryptedData)
        return String(decodedData)
    }
    private fun createAndroidKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }
}
