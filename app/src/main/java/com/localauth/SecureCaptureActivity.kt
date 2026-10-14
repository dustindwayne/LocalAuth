package com.localauth
import android.os.Bundle
import android.view.WindowManager
class SecureCaptureActivity : com.journeyapps.barcodescanner.CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }
}
