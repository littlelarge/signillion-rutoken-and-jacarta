package com.example.tokensigner

import android.content.Context
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11UserType
import ru.rutoken.pkcs11wrapper.rutoken.main.RtPkcs11Token
import ru.rutoken.rtpcscbridge.RtPcscBridge
import ru.rutoken.rttransport.*

class TokenSigner {
    private var transport: RtTransport? = null

    fun initialize(context: Context) {
        try {

            // Инициализация библиотеки
            val initParameters = InitParameters.Builder()
                .setEnabledTokenInterfaces(
                    TokenInterface.USB,
                    TokenInterface.NFC
                ) // Включаем USB и NFC
                .build()

            transport = RtPcscBridge.getTransport()
            transport?.initialize(context, initParameters)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun signHash(token: RtPkcs11Token, hash: ByteArray, userPin: String): ByteArray? {
        return try {
            return token.openSession(true).use { session ->
                return session.login(Pkcs11UserType.CKU_USER, userPin).use {
                    return session.signManager.sign(hash)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun finalize(context: Context) {
        transport?.finalize(context)
    }
}