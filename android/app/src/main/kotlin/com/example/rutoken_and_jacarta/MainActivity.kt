package com.rutoken_and_jacarta

import android.os.Bundle
import com.example.jacarta_sample.Jacarta
import com.example.securekeyplugin.SecureKeyPlugin
import com.signillion.signillion.RutokenSignAndVerify
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugins.GeneratedPluginRegistrant


class MainActivity : FlutterFragmentActivity() {
    private lateinit var jacarta: Jacarta  // Объявляем Jacarta

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        GeneratedPluginRegistrant.registerWith(flutterEngine)
        flutterEngine.plugins.add(SecureKeyPlugin())
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        System.setProperty("jna.nosys", "true")

        val rutokenMode = "Rutoken"
        val jacartaMode = "JaCarta"

        val mode = jacartaMode

        if (mode == rutokenMode) {
        val rutokenSignAndVerify = RutokenSignAndVerify(this)
        rutokenSignAndVerify.initializeRtPcscBridge()

        } else if (mode == jacartaMode) {
        jacarta = Jacarta(this)
            jacarta.onCreate(savedInstanceState)

        }


    }

    override fun onDestroy() {
        super.onDestroy()
        jacarta.onDestroy()
    }

}
