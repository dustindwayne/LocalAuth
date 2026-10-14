package com.localauth
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.*
import org.junit.Test
class QrTest {
 @Test fun decodeAuthenticatorImage() {
  val uri="otpauth://totp/Example%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"
  val matrix=QRCodeWriter().encode(uri,BarcodeFormat.QR_CODE,512,512)
  val pixels=IntArray(512*512){i->if(matrix[i%512,i/512]) 0xff000000.toInt() else 0xffffffff.toInt()}
  val result=MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(512,512,pixels))),mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),DecodeHintType.TRY_HARDER to true))
  val account=Otp.parse(result.text)
  assertEquals("Example:alice",account.label);assertEquals("287082",Otp.code(account,59))
 }
}
