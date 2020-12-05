package com.zsqw123.getsha1

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*


class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this)
        val editTextView = EditText(this)
        editTextView.hint = "输入packagename"
        val bt = Button(this)
        bt.text = "求sha1"
        bt.setOnClickListener {
            editTextView.setText(getCertificateSHA1Fingerprint(editTextView.text.toString()))
        }
        layout.addView(editTextView)
        layout.addView(bt)
        layout.orientation = LinearLayout.VERTICAL
        setContentView(layout)
//        setContentView(R.layout.activity_main)
    }
}


//这个是获取SHA1的方法
fun Context.getCertificateSHA1Fingerprint(packageName: String = ""): String? {
    try {
        //获取包管理器
        val pm: PackageManager = packageManager
        //获取当前要获取SHA1值的包名，也可以用其他的包名，但需要注意，
        //在用其他包名的前提是，此方法传递的参数Context应该是对应包的上下文。
        //返回包括在包中的签名信息
        val packageInfo: PackageInfo = pm.getPackageInfo(if (packageName.isNotEmpty()) packageName else this.packageName, PackageManager.GET_SIGNATURES)
        //签名信息
        val signatures: Array<Signature> = packageInfo.signatures
        val cert: ByteArray = signatures[0].toByteArray()
        //将签名转换为字节数组流
        val input: InputStream = ByteArrayInputStream(cert)
        //证书工厂类，这个类实现了出厂合格证算法的功能
        val cf: CertificateFactory = CertificateFactory.getInstance("X509")
        //X509证书，X.509是一种非常通用的证书格式
        val c: X509Certificate = cf.generateCertificate(input) as X509Certificate
        val hexString: String
        //加密算法的类，这里的参数可以使MD4,MD5等加密算法
        val md: MessageDigest = MessageDigest.getInstance("SHA1")
        //获得公钥
        val publicKey: ByteArray = md.digest(c.encoded)
        //字节到十六进制的格式转换
        hexString = byte2HexFormatted(publicKey)
        return hexString
    } catch (e: PackageManager.NameNotFoundException) {
        e.printStackTrace()
    }
    return null
}

//这里是将获取到得编码进行16进制转换
private fun byte2HexFormatted(arr: ByteArray): String {
    val str = StringBuilder(arr.size * 2)
    for (i in arr.indices) {
        var h = Integer.toHexString(arr[i].toInt())
        val l = h.length
        if (l == 1) h = "0$h"
        if (l > 2) h = h.substring(l - 2, l)
        str.append(h.toUpperCase(Locale.ROOT))
        if (i < arr.size - 1) str.append(':')
    }
    return str.toString()
}
