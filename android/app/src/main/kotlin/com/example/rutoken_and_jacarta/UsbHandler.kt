import android.app.PendingIntent
import android.content.*
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

class UsbHandler(
    private val context: Context,
    private val callback: UsbCallback
) {
    private val usbManager: UsbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    private var usbReceiver: BroadcastReceiver? = null
    private var usbPermissionReceiver: BroadcastReceiver? = null

    interface UsbCallback {
        fun onUsbReady()
        fun onDeviceDetached(message: String)
        fun onPermissionDenied()
        fun onError(message: String)
    }

    fun setupReceivers() {
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }

        usbReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> handleAttach(intent)
                    UsbManager.ACTION_USB_DEVICE_DETACHED -> handleDetach(intent)
                }
            }
        }.also { context.registerReceiver(it, filter) }

        usbPermissionReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                    callback.onUsbReady()
                } else {
                    callback.onPermissionDenied()
                }
            }
        }.also {
            context.registerReceiver(it, IntentFilter(ACTION_USB_PERMISSION))
        }
    }

    fun checkDevices() {
        usbManager.deviceList.values.firstOrNull()?.let {
            if (usbManager.hasPermission(it)) callback.onUsbReady()
            else requestPermission(it)
        }
    }

    private fun handleAttach(intent: Intent) {
        intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)?.let {
            if (usbManager.hasPermission(it)) callback.onUsbReady()
            else requestPermission(it)
        }
    }

    private fun handleDetach(intent: Intent) {
        callback.onDeviceDetached("Device disconnected")
    }

    private fun requestPermission(device: UsbDevice) {
        usbManager.requestPermission(
            device,
            PendingIntent.getBroadcast(
                context,
                0,
                Intent(ACTION_USB_PERMISSION),
                PendingIntent.FLAG_IMMUTABLE
            )
        )
    }

    fun cleanup() {
        usbReceiver?.let { context.unregisterReceiver(it) }
        usbPermissionReceiver?.let { context.unregisterReceiver(it) }
    }

    companion object {
        const val ACTION_USB_PERMISSION = "com.example.jacarta_sample.USB_PERMISSION"
    }
}