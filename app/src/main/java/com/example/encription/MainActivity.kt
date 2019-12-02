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
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import android.os.Build.VERSION_CODES.M
import android.provider.Settings
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


        //   tv2.text=decrypt(tv1.text.toString(),"")


        button.setOnClickListener {
            val input = et.text.toString()
            // Create and Save asymmetric key
            createAndroidKeyStoreAsymmetricKey("MASTER_KEY")

// Get key from keyStore
            var masterKey = getAndroidKeyStoreAsymmetricKeyPair("MASTER_KEY")

// Creates Cipher with given transformation and provides encrypt and decrypt functions
            // var cipherWrapper = CipherWrapper("RSA/ECB/PKCS1Padding")

// Encrypt message with the key, using public key
            var encryptedData = encrypt(input, masterKey?.public)

            tv1.text = encryptedData
            var decryptedData = decrypt(encryptedData, masterKey?.private)
            tv2.text = decryptedData
        }


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


    fun createAndroidKeyStoreAsymmetricKey(alias: String): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")

        if (Build.VERSION.SDK_INT == M) {
            initGeneratorWithKeyGenParameterSpec(generator, alias)
        } else {
            initGeneratorWithKeyPairGeneratorSpec(generator, alias)
        }

        return generator.generateKeyPair()
    }

    fun removeAndroidKeyStoreKey(alias: String) = keyStore.deleteEntry(alias)

    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator, alias: String) {
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 20)

        val builder = if (Build.VERSION.SDK_INT >= JELLY_BEAN_MR2) {
            KeyPairGeneratorSpec.Builder(applicationContext)
                .setAlias(alias)
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=${alias} CA Certificate"))
                .setStartDate(startDate.time)
                .setEndDate(endDate.time)
        } else {
            TODO("VERSION.SDK_INT < JELLY_BEAN_MR2")
        }

        generator.initialize(builder.build())
    }

    @TargetApi(M)
    private fun initGeneratorWithKeyGenParameterSpec(generator: KeyPairGenerator, alias: String) {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        generator.initialize(builder.build())
    }


}
