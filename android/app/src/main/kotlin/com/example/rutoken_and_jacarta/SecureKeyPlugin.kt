package com.example.securekeyplugin

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.NonNull
import androidx.annotation.RequiresApi
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Base64

class SecureKeyPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val ecdsaKeyAlias = "com.signillion.ecdsaKey"
    private val rsaKeyAlias = "com.signillion.rsaKey"
    private val keyStoreType = "AndroidKeyStore"
    private val signatureAlgorithmRSA = "SHA256withRSA"
    private val signatureAlgorithmECDSA = "SHA256withECDSA"

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "secure_key")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateRSAKeyPair" -> generateRSAKeyPair(result)
            "generateECDSAKeyPair" -> generateECDSAKeyPair(result)
            "signHash" -> {
                val args = call.arguments as? Map<*, *>
                val hashString = args?.get("hash") as? String
                val algorithm = args?.get("algorithm") as? String
                if (hashString.isNullOrEmpty()) {
                    result.error("INVALID_ARGUMENTS", "Missing hash", null)
                } else {
                    signHashWithPrivateKey(hashString.toByteArray(), algorithm, result)
                }
            }

            else -> result.notImplemented()
        }
    }


    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateRSAKeyPair(result: MethodChannel.Result) {
        try {
            val keyStore = KeyStore.getInstance(keyStoreType).apply { load(null) }
            if (keyStore.containsAlias(rsaKeyAlias)) {
                val publicKey = keyStore.getCertificate(rsaKeyAlias).publicKey
                val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.encoded)

                Log.d("tag", publicKeyBase64.toString())

                result.success(
                    mapOf(
                        "publicRSAKey" to publicKeyBase64,
                        "generated" to "false"
                    )
                )
                return
            }
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, keyStoreType
            )
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                rsaKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(2048)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .build()

            keyPairGenerator.initialize(keyGenParameterSpec)

            val keyPair = keyPairGenerator.generateKeyPair()

            val publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

            result.success(
                mapOf(
                    "publicRSAKey" to publicKeyBase64,
                    "generated" to "true"
                )
            )
        } catch (e: Exception) {
            result.error("KEY_GEN_ERROR", "Key generation failed: ${e.localizedMessage}", null)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateECDSAKeyPair(result: MethodChannel.Result) {
        try {
            val keyStore = KeyStore.getInstance(keyStoreType).apply { load(null) }
            if (keyStore.containsAlias(ecdsaKeyAlias)) {
                val publicKey = keyStore.getCertificate(ecdsaKeyAlias).publicKey
                val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.encoded)

                result.success(
                    mapOf(
                        "publicECDSAKey" to publicKeyBase64,
                        "generated" to "false"
                    )
                )
                return
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, keyStoreType
            )
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                ecdsaKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .build()

            keyPairGenerator.initialize(keyGenParameterSpec)

            val keyPair = keyPairGenerator.generateKeyPair()

            val publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

            result.success(
                mapOf(
                    "publicECDSAKey" to publicKeyBase64,
                    "generated" to "true"
                )
            )
        } catch (e: Exception) {
            result.error("KEY_GEN_ERROR", "Key generation failed: ${e.localizedMessage}", null)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun signHashWithPrivateKey(
        hash: ByteArray,
        algorithm: String?,
        result: MethodChannel.Result
    ) {
        try {
            val keyStore = KeyStore.getInstance(keyStoreType)
            keyStore.load(null)
            val keyAliasToUse = if (algorithm == "ECDSA") ecdsaKeyAlias else rsaKeyAlias
            val privateKey = keyStore.getKey(keyAliasToUse, null) as java.security.PrivateKey

            val signatureAlgorithm =
                if (algorithm == "ECDSA") signatureAlgorithmECDSA else signatureAlgorithmRSA

            val signature = Signature.getInstance(signatureAlgorithm)
            signature.initSign(privateKey)
            signature.update(hash)
            val signedHash = signature.sign()
            val signedHashString = Base64.getEncoder().encodeToString(signedHash)

            result.success(signedHashString)
        } catch (e: Exception) {
            e.printStackTrace()
            result.error("SIGN_ERROR", "Sign failed: ${e.localizedMessage}", null)
        }
    }
}
