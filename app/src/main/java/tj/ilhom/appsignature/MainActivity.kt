package tj.ilhom.appsignature

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class MainActivity : AppCompatActivity() {
    companion object {
        init {
            System.loadLibrary("native-lib")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Example of a call to a native method
        val tv = findViewById(R.id.sample_text) as TextView
        var info: PackageInfo? = null
        try {
            info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }
        if (null != info && info.signatures.size > 0) {
            val rawCertJava = info.signatures[0].toByteArray()
            val rawCertNative = bytesFromJNI(this)
            val str = """
            Signature MD5 
            
            From Java:
            ${getInfoFromBytes(rawCertJava)}
            
            From native:
            $rawCertNative
            """.trimIndent()
            tv.text = str
        } else {
            tv.text = "No data"
        }
    }

    private fun getInfoFromBytes(bytes: ByteArray?): String {
        if (null == bytes) {
            return "null"
        }
        val sb = StringBuilder()
        try {

            var md: MessageDigest
            try {
                md = MessageDigest.getInstance("MD5")
                md.update(bytes)
                var byteArray = md.digest()
                //String hash_key = new String(Base64.encode(md.digest(), 0));
                sb.append("MD5: ").append(bytesToString(byteArray)).append("\n")
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
            sb.append("\n")
        } catch (e: CertificateException) {
            // e.printStackTrace();
        }
        return sb.toString()
    }


    private fun bytesToString(bytes: ByteArray): String? {
        val md5StrBuff = StringBuilder()
        for (i in bytes.indices) {
            if (Integer.toHexString(0xFF and bytes[i].toInt()).length == 1) {
                md5StrBuff.append("0").append(Integer.toHexString(0xFF and bytes[i].toInt()))
            } else {
                md5StrBuff.append(Integer.toHexString(0xFF and bytes[i].toInt()))
            }
            if (bytes.size - 1 != i) {
                md5StrBuff.append("")
            }
        }
        return md5StrBuff.toString()
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    private external fun bytesFromJNI(context: Context): String
}