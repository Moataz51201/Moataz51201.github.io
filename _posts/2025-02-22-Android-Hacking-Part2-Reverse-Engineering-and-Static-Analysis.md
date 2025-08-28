---
layout: post
title: "Android Hacking Part2 : Reverse Engineering and Static Analysis"
date: 2025-08-26
categories: [Android Pentesting,Android Apps,Operating Systems,Mobile Development]
image: https://cdn-images-1.medium.com/max/800/1*zbiREAm7w5GmASuSHlojyA.jpeg
---

#### Reversing

In this part we will extract the legitimate apk from emulator or the device and get the source code.

#### TOOLS

**Android Debug Bridge (ADB)** is a development tool that facilitates communication between an Android device and a personal computer.

[How to Install ADB on Windows, macOS, and Linux](https://www.xda-developers.com/install-adb-windows-macos-linux/)

**Note**: You need debug usb enable in your emulator or device.

**How view devices?**

> adb devices

![](https://cdn-images-1.medium.com/max/800/1*CQp8TVswMeNUEgK5MLq83Q.png)

**How extract apk?**

For this you need have installed the application in your device and know package name

> adb shell pm path package\_name

This command print the path to the APK of the given

![](https://cdn-images-1.medium.com/max/800/1*zS8I1YjSPv8I0OC2sIz0bQ.png)

> adb pull <remote> \[<locaDestination>\]

This command pulls the file **remote** to **local**. If **local** isn’t specified, it will pull to the current folder.

![](https://cdn-images-1.medium.com/max/800/1*V11Sq1I9fFFRuqP8dLlUkw.png)

Now,how a get source code?

[**jadx**](https://github.com/skylot/jadx/releases/)**:** The **jadx** suite allows you to simply load an APK and look at its Java source code. What’s happening under the hood is that jADX is decompiling the APK to smali and then converting the smali back to Java.

**jadx-gui:** UI version of jadx

[**Dex2Jar**](https://sourceforge.net/projects/dex2jar/): use dex2jar to convert an APK to a JAR file.

Once you have the JAR file, simply open it with [**JD-GUI**] and you’ll see its Java code.

[apktool](https://ibotpeaches.github.io/Apktool/install/): This tool get a source code in smali.

> apktool d file.apk

- - -

### Start with the OWASP Mobile Top Ten to find vulnerabilities

The Open Web Application Security Project (OWASP) is a nonprofit foundation that provides security tips and methodologies mainly for web applications. If you’re new to Android penetration testing, these vulnerabilities are a great starting point that will help you find flaws and improve application security:

#### M1 : Improper Credential Usage

> **_Definition:_** _Improper handling of credentials (passwords, API keys, tokens) in mobile applications, making them easy to extract or misuse._

**Examples:**

*   **Hardcoded Credentials in APK:**

> `_strings app.apk | grep "API_KEY"_`

The app contains hardcoded credentials in the source code, making it easy for attackers to extract them.

*   **Sensitive Data Stored in Shared Preferences (ADB Extraction Example)**

> `_adb shell cat /data/data/app.name/shared_prefs/auth_prefs.xml_`

The app stores authentication tokens in unencrypted Shared Preferences, making them accessible if the device is compromised.

*   **Unprotected External Storage (Accessible by Any App)**

> `_file:///mnt/sdcard/.uinfo.txt_`

The app stores user credentials in a hidden file on external storage, which any app with storage permissions can read.

**Mitigation**:

*   **Use the Android Keystore** to store authentication tokens securely.
*   **Do not store API keys or secrets in the app**; use a backend API with token-based authentication.
*   **Use EncryptedSharedPreferences** for less sensitive data but avoid using it for passwords or API keys.
*   **Avoid storing credentials in external storage** unless encrypted.

- - -

#### M2: Inadequate Supply Chain Security

#### Overview

Supply chain security risks arise when attackers compromise an application’s components **before deployment**, targeting third-party dependencies, CI/CD pipelines, or distribution channels. This can lead to malicious modifications that go undetected until the app reaches users.

#### Common Attack Scenarios

1.  **Dependency Confusion & Malicious Third-Party Libraries**

Many apps rely on third-party libraries or SDKs. Attackers exploit this by **publishing malicious versions** of legitimate dependencies to public repositories.

**Example:** A developer’s app depends on `com.company:securelib:1.0`, which exists internally but not in a public repository. An attacker uploads `securelib:2.0` to **Maven Central**, tricking the build system into fetching the malicious version.

dependencies {  
    implementation 'com.company:securelib:2.0' // Attacker's malicious version  
}

**Mitigation:** Use **private package registries**, verify dependencies with **hash signatures**, and enable **allowlist restrictions**.

**2\. Compromised CI/CD Pipeline (Build System Backdoor)**

Attackers may **inject malicious code** into an application’s build pipeline, modifying the source code **without developer awareness**.

**Example**:

An attacker gains access to a company’s **Jenkins/GitHub Actions pipeline** and inserts a **malicious script**:

> `_steps: - name: Inject malware_`

> `_run: echo 'malware_code' >> app/src/main/java/MainActivity.java_`

The app is **built, signed, and distributed** with the malware inside.

**Mitigation:** Use **code-signing**, enforce **build integrity checks** (`sigstore`), and monitor CI/CD pipelines for anomalies.

**3\. APK Tampering & Unauthorized Distribution**

If an app is distributed outside of **official stores** (Play Store, App Store), attackers can **modify and redistribute** it as a trojanized version.

**Example:**

*   A banking app’s **official APK** is leaked.
*   The attacker **modifies the code**, inserting a **keylogger** to steal credentials:

> `_apktool d bank.apk -o modified_bank_`

> `_echo 'malicious code' >> modified_bank/smali/com/bank/Login.smali_`

> `_apktool b modified_bank -o trojan.apk_`

The trojan APK is **re-signed** and distributed via Telegram, WhatsApp, or third-party stores.

**Mitigation**:  
**. Use Play Integrity AP**I to detect modified APKs.  
**. Enforce app signature verificatio**n before execution.  
**. Distribute via trusted channel**s (Google Play, MDM solutions).

#### App Signing Example:

#### 1\. Decompiling the APK (Extracting Contents)

apktool d diva-beta.apk -r -f

*   `**d**` → Decompile the APK.
*   `**-r**` → Prevents decompiling resources (useful when you only want to modify smali files).
*   `**-f**` → Forces overwriting of any existing directory (`**diva-beta/**`**).**

After this, the contents of `**diva-beta.apk**` will be extracted into the `**diva-beta**/` folder.

#### 2\. Rebuilding the APK (After Modifications)

apktool b diva-beta/ -o test.apk

*   `**b**` → Builds the modified APK.
*   `**-o test.apk**` → Specifies the output file name as `**test.apk**`.

At this stage, `**test.apk**` is unsigned and needs to be signed before installation.

#### 3\. Verifying the Unsigned APK

jarsigner -verify test.apk

*   This checks whether `**test.apk**` is signed.
*   It will likely show an error since the APK is not yet signed.

#### 4\. Generating a Keystore

keytool \-genkey \-v \-keystore diva.keys \-alias testdiva \-keyalg RSA \-keysize 2048 \-validity 3650

*   `**-genkey**` → Generates a new keystore.
*   `**-keystore diva.keys**` → Saves the keystore as `**diva.keys**`**.**
*   `-**alias testdiva**` → Alias name for the key.
*   `**-keyalg RSA**` → Uses RSA encryption.
*   `**-keysize 2048**` → Sets key length to 2048 bits.
*   `-**validity 3650**` → Valid for 10 years.

You’ll be prompted to enter details like name, organization, and password (`**diva1234**` in this case).

#### 5\. Signing the APK

jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore diva.keys -storepass diva1234 test.apk testdiva

*   `**-sigalg** **SHA1withRSA**` → Uses SHA1 hashing with RSA signing.
*   `**-digestalg SHA1**` → Uses SHA1 for digesting (note: SHA1 is deprecated; consider using SHA-256).
*   `**-keystore diva.keys**` → Uses `**diva.keys**` keystore.
*   `**-storepass diva1234**` → Password for keystore.
*   `**test.apk testdiva**` → Signs `**test**.**apk**` using the alias `**testdiva**`.

#### 6\. Verifying the Signed APK

jarsigner -verify -verbose test.apk

*   This checks the validity of the signature.

If everything is correct, you should see `**jar verified**`**.**

#### 7\. Extracting Certificate Information

cd META-INF | keytool -printcert -file testdiva.RSA

*   `**cd META-INF**` → Changes to the `META-INF/` directory inside the APK.
*   `**keytool -printcert -file testdiva.RSA**` **→** Displays the certificate details from `**testdiva.RSA**`.

- - -

#### M3 : Insecure Authentication/Authorization

#### Overview

Insecure authentication and authorization flaws occur when an application fails to **properly verify** a user’s identity or privileges. Attackers can **bypass login mechanisms**, escalate privileges, or access restricted functionalities by **manipulating intents, APIs, or session tokens**.

#### Common Attack Scenarios

#### 1\. Bypassing Authentication Using ADB Commands

If an application relies solely on **client-side checks** without server-side verification, attackers can use **Android Debug Bridge (ADB)** to bypass authentication and access restricted activities.

**Example:**  
The following ADB command directly launches a protected activity **without authentication**:

adb shell am start -n jjj.ass.diva/.APICreds2Activity -a jjj.ass.diva.action/.VIEW\_CREDS2 -ez check\_pin false

**Risk:** The app fails to validate authentication at the backend, allowing unauthorized users to open sensitive activities.

**Mitigation:**  
. Restrict access to activities using **custom permissions** (`android:permission`).  
. Validate user authentication **on the server side** instead of relying on **client-side logic**.  
. Disable **exported** activities in `AndroidManifest.xml` if not required.

#### 2\. Broken API Authentication

If an API does not properly validate session tokens or roles, attackers can **modify API requests** to access unauthorized endpoints.

**Example:**  
A banking app’s API validates users via a simple session cookie:

GET /user/profile HTTP/1.1    
Host: api.bank.com    
Cookie: session\_id=12345

An attacker changes the session ID to another user’s session:

Cookie: session\_id=99999

**Risk:** The server does not validate whether the session actually belongs to the logged-in user.

**Mitigation:**  
. Implement **token-based authentication** (JWT/OAuth2).  
. Use **session binding** to prevent token reuse across different devices.  
. Enforce **server-side role-based access control (RBAC)**.

#### 3\. Insecure Local Authentication (Hardcoded PINs or Credentials)

If an app uses **hardcoded credentials** or weak authentication mechanisms, attackers can decompile the app and extract credentials.

**Example:**  
Decompiling the APK reveals **hardcoded PIN authentication** inside `LoginActivity.smali`:

const\-string v0, "1234"  \# Hardcoded PIN  
invoke-static {v0}, Ljjj/ass/diva/LoginActivity;->checkPin(Ljava/lang/String;)Z

**Risk:** Attackers can **bypass authentication** by using the hardcoded PIN.

**Mitigation**:  
. Avoid **storing authentication logic in the clien**t.  
. Use **biometric authentication (Fingerprint/FaceID**) instead of PINs.  
. Implement **multi-factor authentication (MFA**) for added security.

- - -

#### M4: Insufficient Input/Output Validation

#### Overview

Mobile applications often fail to properly validate user input or sanitize output, leading to **security vulnerabilities** such as:

*   **SQL Injection** (Manipulating database queries)
*   **Intent Manipulation** (Bypassing app logic)
*   **Local File Inclusion (LFI)** (Accessing restricted files)
*   **Untrusted Deserialization** (Injecting malicious objects)

These flaws allow attackers to **bypass authentication, steal data, or execute arbitrary code** on the device.

#### Common Attack Scenarios in Mobile Apps

#### 1\. SQL Injection via Unvalidated Input Fields

**Example:**  
If a mobile app does not sanitize input before executing SQL queries, an attacker can inject malicious SQL commands to bypass authentication.

**Test with ADB (Android Debug Bridge):**

adb shell am start -n com.example.app/.LoginActivity --es username "' OR '1'='1" --es password "anything"

**Risk:**

*   The app executes the query without validation:

> `_SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';_`

*   Since `'1'='1'` is always true, **any user can log in** without valid credentials.

**Mitigation:**  
. Use **parameterized queries** (`SQLiteDatabase.query()`).  
. Validate input using **allowlists** instead of blocking specific characters.  
. Implement **secure database encryption** to protect stored data.

#### 2\. Intent Manipulation to Bypass App Logic

**Example:**  
Many Android apps use **intents** to pass data between activities. If not properly secured, attackers can manipulate these intents to access unauthorized functionality.

**Exploit using ADB:**

adb shell am start -n com.example.app/.AdminPanelActivity --es admin "true"

**Risk:**

*   Attackers **trigger hidden activities** that should only be accessible to admins.
*   Can lead to **data leaks or privilege escalation**.

**Mitigation:**  
. Validate intent extras before processing (`getBooleanExtra()`).  
. Use **signature-level permissions** for sensitive activities.  
. Implement **backend authorization checks** to prevent bypassing security via local modifications.

#### 3\. Local File Inclusion (LFI) via Unvalidated Input

**Example:**  
If an app loads files based on user input, attackers can access **internal storage files**, potentially leaking sensitive data.

**Exploit via ADB:**

adb shell am start -n com.example.app/.FileViewerActivity --es file "../../../../data/system/users/0.xml"

**Risk:**

*   Can **expose user credentials, tokens, or logs**.
*   Might allow **remote code execution** in certain cases.

**Mitigation:**  
. Use **whitelisting** to limit file access.  
. Validate input using **canonical path checks** (`File.getCanonicalPath()`).  
. Store sensitive data in **encrypted storage**, not in raw files.

#### 4\. Insecure Deserialization Allowing Code Execution

**Example:**  
Some mobile apps deserialize untrusted data without proper validation, leading to **Remote Code Execution (RCE)**.

**Exploit via Frida (Dynamic Analysis Tool):**

hook = """  
Java.perform(function() {  
    var ObjectInputStream = Java.use("java.io.ObjectInputStream");  
    ObjectInputStream.readObject.implementation = function() {  
        console.log("Deserializing object...");  
        return this.readObject();  
    };  
});  
"""

**Risk:**

*   Attackers can craft **malicious serialized objects** and execute arbitrary code.
*   Could lead to **device compromise**.

**Mitigation:**  
. Use **secure serialization formats** like **Protobuf or JSON**, avoiding Java serialization.  
. Implement **object validation checks** before deserialization.

. Enforce **strict input validation** when accepting serialized data.

- - -

#### M5 : Insecure Communication

#### · Overview

Mobile applications often transmit sensitive data (e.g., authentication tokens, API requests, personal information) over **network channels** such as:

*   HTTP requests
*   WebSockets
*   Content Providers
*   Custom Inter-Process Communication (IPC)

If these channels **lack encryption or proper access controls**, attackers can intercept or manipulate data, leading to **data leakage, man-in-the-middle (MITM) attacks, and unauthorized access**.

- - -

#### Common Attack Scenarios in Mobile Apps

#### 1\. Exploiting Insecure Content Providers

**Exploit via ADB:**

content query \--uri content://jjj.ass.diva.provider.>

**Risk:**

*   Many Android apps expose **Content Providers** without proper access controls.
*   Attackers can query and retrieve **sensitive data (e.g., user credentials, messages, tokens)**.

**Mitigation:**  
. Secure Content Providers with **permission-based access controls** (`android:permission` in `AndroidManifest.xml`).  
. Use **URI permissions** (`FLAG_GRANT_READ_URI_PERMISSION`) to restrict unauthorized access.  
. **Encrypt stored data** to prevent data leaks even if accessed.

#### 2\. Intercepting Unencrypted HTTP Requests

#### Exploit using Burp Suite (MITM Attack)

. Set up **Burp Proxy** and capture app traffic.  
. If the app uses **HTTP instead of HTTPS**, intercept **sensitive API calls** (login, payment, etc.).

**Risk**:

*   Attackers can steal **session tokens, passwords, or API keys** in plaintext.
*   MITM attacks allow **modifying API responses** (e.g., changing account balances).

**Mitigation:**  
. Always use **TLS 1.2/1.3** for secure communication (`https://` instead of `http://`).  
. **Enforce HTTPS** using **Network Security Configuration** in `res/xml/network_security_config.xml`:

<network-security-config\>  
    <domain-config cleartextTrafficPermitted\="false"\>  
        <domain includeSubdomains\="true"\>your-api.com</domain\>  
    </domain-config\>  
</network-security-config\>

Implement **certificate pinning** to prevent MITM attacks.

#### 3\. Exposing Sensitive Data via WebSockets

**Exploit using WebSocket Interception (Burp Suite or MITM Proxy)**  
Identify WebSocket traffic (`ws://` instead of `wss://`).

Capture and modify messages in real-time.

**Risk**:

*   Attackers can **spoof requests**, manipulate real-time data, or hijack sessions.
*   Sensitive data (e.g., **chat messages, payment transactions**) can be **stolen or altered**.

**Mitigation:**  
. Always use **WSS (WebSockets over TLS)** instead of **WS**.  
. Implement **message signing** to ensure data integrity.  
. Use **JWT tokens** with short expiration times for authentication.

#### 4\. Leaking Sensitive Data via Logcat

**Exploit using ADB:**

adb logcat | grep "password"

**Risk:**

*   Some apps **log sensitive information** like **passwords, API keys, or user tokens**.
*   Attackers with ADB access can retrieve this data easily.

**Mitigation:**  
. **Never log sensitive data** in production (`Log.d()` should be removed or obfuscated).  
. Use **ProGuard or R8 obfuscation** to prevent reverse engineering.  
. Encrypt logs before storing them in persistent storage.

- - -

#### M6: Inadequate Privacy Controls

#### Overview

Mobile apps handle sensitive **Personally Identifiable Information (PII)**, such as:

*   **Usernames, email addresses, phone numbers**
*   **Location data** (GPS, IP addresses)
*   **Payment details**
*   **Authentication tokens & session data**

If privacy controls are **poorly implemented**, attackers can **steal, misuse, or leak PII**, violating user privacy and regulations (e.g., GDPR, CCPA).

- - -

#### Common Privacy Vulnerabilities in Mobile Apps

#### 1\. Storing PII in Logs

**Exploit using ADB:**

adb logcat | grep "email"

**Risk:**

*   If an app logs sensitive data (e.g., email, passwords, session tokens), an attacker with **ADB access** can extract them.
*   Logs are often stored in `/data/logs/`, which can be accessed if the device is **rooted**.

**Mitigation:**  
. **Never log PII** in production (`Log.d()` and `System.out.println()` should be removed).  
. Use **Android’s Privacy Sandbox** for handling sensitive data.  
. **Encrypt logs** before writing them to files.

#### 2\. Storing PII in URL GET Parameters

**Exploit using Burp Suite or MITM Proxy:**  
. Intercept network traffic.  
. Check if PII (e.g., user ID, tokens) is exposed in URLs:

https://example.com/profile?user=admin&token=123456

**Risk:**

*   URLs are **logged in browser history, server logs, and proxies**.
*   Attackers can extract **session tokens, API keys, or passwords**.

**Mitigation:**  
. Always send PII in **POST requests** instead of **GET requests**.  
. Use **OAuth tokens or session cookies** instead of exposing credentials.  
. **Encrypt request payloads** and avoid hardcoding secrets in URLs.

#### 3\. Storage of PII After Logout/App Closure

**Exploit using ADB:**

adb shell run-as com.example.app cat /data/data/com.example.app/shared\_prefs/user.xml

**Risk:**

*   Many apps store **session tokens, authentication data, and user details** in **SharedPreferences or SQLite databases** without clearing them on logout.
*   Attackers with **root access** can retrieve these files and restore sessions.

**Mitigation:**  
. **Clear sensitive data** upon logout (`SharedPreferences.Editor.clear()`).  
. **Use Secure Storage APIs** (`EncryptedSharedPreferences`, `KeyStore`).  
. Implement **Auto-Logout** after a period of inactivity.

- - -

#### M7: Insufficient Binary Protection

#### Overview

Mobile apps often **lack binary protections**, making them vulnerable to:

*   **Reverse engineering** (analyzing app logic, API endpoints, cryptographic keys).
*   **Repackaging & code injection** (modifying APKs to bypass security or add malware).
*   **Tampering & dynamic analysis** (altering app behavior using Frida, Magisk, or Xposed).

- - -

#### Common Binary Protection Weaknesses & Exploits

#### 1\. App Log Monitoring for Debugging Information

**Exploit using ADB Logcat:**

adb logcat | grep "pid"

**Risk:**

*   Logs can **leak sensitive app data**, including API keys, user credentials, or internal errors.
*   Attackers can analyze logs to find vulnerabilities (e.g., hardcoded secrets, crash dumps).

**Mitigation:**  
. **Disable logging in production** (`Log.d()`, `System.out.println()` should be removed).  
. Use **ProGuard/R8** to obfuscate logs and prevent sensitive information exposure.  
. **Implement log access restrictions** using SELinux policies.

- - -

#### 2\. Reverse Engineering the APK

**Exploit using JADX & APKTool:**

jadx-gui app.apk  \# Decompile APK for source code analysis  
apktool d app.apk \# Disassemble APK to modify resources

**Risk:**

*   Attackers can **extract API keys, encryption logic, or internal functions**.
*   Allows **cloning, malware injection, and bypassing authentication**.

**Mitigation:**  
. **Obfuscate code using ProGuard or R8** to make reverse engineering harder.  
. Use **Android App Bundles (AAB)** instead of APKs to limit exposure.  
. **Encrypt strings & API keys** using `Android Keystore` or runtime decryption.

#### 3\. Modifying & Repackaging the APK

**Exploit using APKTool + Smali Injection:**

apktool d app.apk -o extracted\_apk  
\# Modify smali files to disable authentication  
apktool b extracted\_apk -o modified.apk

**Risk:**

*   Attackers can **remove security checks, inject malicious code, and distribute fake apps**.
*   Example: **Modifying banking apps** to bypass two-factor authentication (2FA).

**Mitigation:**  
. **Implement signature verification** to detect repackaging.  
. Use **Google Play Integrity API / SafetyNet Attestation** for runtime verification.  
. **Prevent app execution on rooted devices** using root detection techniques.

#### 4\. Runtime Hooking & Memory Tampering

**Exploit using Frida to Bypass Security Checks**:

frida -U -n com.example.app -e 'Interceptor.attach(Module.findExportByName(null, "strcmp"), { onEnter: function(args) { args\[1\] = ptr("0"); } })'

**Risk:**

*   Attackers can **bypass authentication**, intercept API requests, or modify game scores.
*   Example: **Disabling SSL pinning to intercept HTTPS traffic**.

**Mitigation:**  
. **Detect Frida & dynamic analysis tools** by checking for suspicious processes.  
. Use **JNI/C++ code** for critical logic to make hooking harder.  
. **Implement memory integrity checks** (`ptrace()` anti-debugging techniques).

- - -

#### M8: Security Misconfiguration

· Overview

Security misconfigurations in mobile applications occur when developers leave unintended or insecure features in the app. This could be debug backdoors, hidden activities, or unprotected features that can be exploited by attackers. These misconfigurations often go unnoticed during production releases and can be leveraged for attacks, including unauthorized access, data leaks, or privilege escalation.

- - -

#### Common Exploits and Vulnerabilities

#### 1\. Hidden Debugging Backdoors

**Exploit Example: ADB Hidden Activity Access**

adb shell am start -n com.mwr.example.sieve/com.mwr.example.sieve.PWList

**Risk:**

*   **Hidden Activities:** Developers may leave test or debugging activities enabled, which can be accessed through ADB commands.
*   **Backdoor Features:** Attackers can invoke features that were not intended to be exposed (e.g., viewing or modifying sensitive data).

**Mitigation:**  
. **Disable debugging** (`android:debuggable="false"`) in the `AndroidManifest.xml`.  
. **Remove all debugging code** before releasing the app.  
. Ensure that **only essential features** are included in the release version, and **no test-specific logic** remains in the codebase.

#### 2\. Exposed Developer Tools or Settings

**Exploit Example: Exposing Developer Tools in Production**  
Developers may leave **developer tools, logs, or admin functions** exposed in the production app, either accidentally or during testing. These can allow attackers to retrieve sensitive information or take control over app functions.

**Risk:**

*   **Unsecured endpoints or internal settings** can be exploited by attackers to gain control over the app.
*   **Sensitive information** such as hardcoded API keys or internal configuration details can be easily accessed.

**Mitigation:**  
. Use **penetration testing tools** such as **Drozer** or **MobSF** to identify exposed endpoints, hidden activities, and other security misconfigurations.  
. **Minimize the permissions and visibility** of sensitive features.  
. **Ensure a secure build process** that strips out any unnecessary files or tools before production release.

#### 3\. Improper Permissions or Exposed Services

**Exploit Example: Exposing Sensitive Services or Permission**s  
Sometimes, applications may leave **services or broadcast receivers expose**d without proper permissions, which attackers can exploit to trigger activities or gain sensitive data. These services may allow unauthorized users or apps to interact with them, bypassing security mechanisms.

**Risk:**

*   **Unauthorized access** to exposed components or services can allow attackers to manipulate app behavior or steal data.

**Mitigation:**  
. **Restrict access to sensitive services** via proper permission settings in `AndroidManifest.xml`.  
. **Use custom permissions** to tightly control access to sensitive resources and features.

- - -

#### M9: Insecure Data Storage

#### Overview

Storing sensitive data such as passwords, API keys, or user information in unprotected locations on a mobile device can lead to severe security risks. These locations can include shared preferences, SQLite databases, and unprotected external storage. If an attacker gains root access or uses tools like ADB, they can extract and analyze this sensitive data, leading to potential compromise.

- - -

#### Common Exploits and Vulnerabilities

#### 1\. Sensitive Data in Shared Preferences

**Exploit Example: Accessing Shared Preferences**

cd /data/data/app.name/shared\_prefs

**Risk:**

*   **SharedPreferences** are often used to store app configuration data, but if sensitive data such as user credentials or tokens are stored in plain text, attackers can easily access them by navigating to the shared\_prefs directory using ADB or a rooted device.

**Mitigation:**  
. **Use EncryptedSharedPreferences** instead of plain SharedPreferences. This ensures that data is encrypted at rest, making it harder for attackers to read.  
. **Avoid storing sensitive information** in SharedPreferences entirely if possible.

#### 2\. Sensitive Data in Unprotected SQLite Databases

**Exploit Example: Extracting Database Information**

adb pull /data/data/app.name/databases/ids2

**Risk:**

*   **SQLite databases** often contain critical app data and may be improperly secured. If these databases are not encrypted, an attacker with root access or via ADB can pull them off the device and read sensitive information.

**Mitigation:**  
. **Encrypt database contents** using tools like SQLCipher to ensure data remains protected.  
. **Limit access** to the app’s database by enforcing proper access control mechanisms.

#### 3\. Sensitive Data in External Storage

**Exploit Example: Reading from External Storage**

file:///mnt/sdcard/.uinfo.txt

**Risk:**

*   **External storage** is typically unprotected and can be accessed by any app on the device. Storing sensitive data like user info or session tokens in unencrypted files on external storage poses a significant risk.

**Mitigation:**  
. **Never store sensitive data** in external storage. If storing non-sensitive data in external storage is unavoidable, make sure it is encrypted.  
. **Use Android’s secure storage mechanisms** (such as **Android Keystore** and **EncryptedSharedPreferences**) to store sensitive data.

- - -

#### M10: Insufficient Cryptography

#### Overview

Insecure cryptographic practices are a significant vulnerability in mobile applications. When an app uses weak cryptography or hardcodes cryptographic keys, attackers can reverse-engineer the app and easily access sensitive data, such as encryption keys or private user information.

- - -

#### Exploit Example: Extracting Hardcoded Keys

#### Example Command:

cd app\\base\\lib\\x86 | strings .\\libdivajni.so

This command allows an attacker to search for plaintext strings in the native library of an app (in this case, `libdivajni.so`) and potentially extract hardcoded cryptographic keys used by the app.

#### Risk:

If the app uses weak encryption or hardcoded cryptographic keys, an attacker can reverse-engineer the APK or inspect native libraries to extract sensitive information such as encryption keys, API keys, or user credentials. For instance, hardcoded **AES keys** in the app, or using weak modes like **ECB (Electronic Codebook)**, can lead to vulnerabilities where data can be easily decrypted.

- - -

#### Examples of Weak Cryptography

*   **Hardcoded AES keys** in the app’s code or native libraries, which can be extracted through reverse engineering.
*   **Weak encryption modes** such as ECB (Electronic Codebook), which do not provide semantic security (same plaintext always maps to the same ciphertext).
*   **Storing cryptographic keys** in insecure locations like SharedPreferences, which are not properly encrypted.

#### Mitigation Strategies

#### 1\. Secure Key Storage

*   **Android Keystore API**: Use the **Android Keystore API** to store cryptographic keys securely. The Keystore uses hardware-backed security to protect keys, making them inaccessible to an attacker, even if they have root access to the device.

#### 2\. Use Strong Encryption Algorithms

*   Always use **AES-256** encryption with **GCM (Galois/Counter Mode)** instead of ECB. GCM provides authenticated encryption and ensures the integrity and confidentiality of the encrypted data.

#### 3\. Avoid Hardcoding Keys

*   Do not hardcode encryption keys in your source code or native libraries. Instead, store keys securely using the **Android Keystore API** or use key management systems.

#### 4\. Avoid Weak Encryption

*   **ECB mode** should be avoided as it has significant security flaws. Use **CBC (Cipher Block Chaining)** or **GCM** instead, which are more secure because they introduce randomness into the encryption process and prevent patterns from emerging.

- - -

#### [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-documentation)

My favorite tool is Mobile Security Framework (**MobSF**) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.

![](https://cdn-images-1.medium.com/max/800/1*i21sFpzUjCm1QB3tbunvcw.png)

#### Key Features of MobSF

1.  **Information**

Displays key data about the app, such as:

*   App icon, app name, size, and package name.
*   **MD5** & **SHA1** hashes, which can help detect if the app is known to be malicious.

**2\. Scan Options**

*   **Rescan** the application: Rerun an analysis to get updated results.
*   **Dynamic Analysis**: Start analyzing the app while it runs on a real or virtual device.
*   **Java Code and Manifest File Review**: Inspect the app’s Java code and AndroidManifest.xml for vulnerabilities.

**3\. Signer Certificate**

*   Displays certificate details, such as the **signer’s certificate** information.
*   Determines if the app originates from its **original source**, providing insight into its trustworthiness.

**4\. Permissions**

*   Analyzes **permissions** requested by the app.
*   Assesses the **criticality** of these permissions and provides a description of each permission’s potential risks.

**5\. Binary Analysis**

*   Performs a **binary code analysis** to assess the app at the binary level.
*   Identifies issues with **third-party libraries** and their potential impact on the app’s security.

**6\. Android API Usage**

*   Identifies **Android API calls** used by the app, including sensitive functions like **Java reflection** and **location access**.

**7\. Browsable Activities**

*   Identifies activities within the app that can be **invoked safely** from a browser.

**8\. Security Analysis**

*   **Manifest Analysis**: Scans the **AndroidManifest.xml** file for vulnerabilities.
*   **Code Analysis**: Uses static code analysis tools to examine Java code and identifies potential vulnerabilities.
*   Vulnerabilities are assigned a **CVSS (Common Vulnerability Scoring System)** score, helping to assess their **severity**.
*   The system also includes the **CWE (Common Weakness Enumeration)** list for weaknesses in software design or code.
*   **File Analysis**: Examines files within the app to check for any security issues.

**9\. Malware Analysis**

*   Analyzes **malware** samples to determine their functionality, origin, and potential impact on the app or device.

**10\. Reconnaissance**

*   **URL Analysis**: Displays URLs, IP addresses, and other data sources used by the app to send or receive information.
*   **Strings Analysis**: Examines text files within the app’s **res** directory, which may contain sensitive data.

- - -

#### Static analysis — Complications

**Obfuscate Code:**

is the process of modifying an executable so that it is no longer useful to a hacker but remains fully functional. While the process may modify actual method instructions or metadata, it does not alter the output of the program. To be clear, with enough time and effort, almost all code can be reverse engineered. However, on some platforms (such as Java, Android, iOS and .NET) free decompilers can easily reverse-engineer source code from an executable or library in virtually no time and with no effort. Automated code obfuscation makes reverse-engineering a program difficult and economically unfeasible.

**Proguard**:

![](https://cdn-images-1.medium.com/max/800/1*tByAvPjPEECFJ0YHKxYGoA.png)

To obfuscate the code, use the Proguard utility, which makes these actions:

Removes unused variables, classes, methods, and attributes;

Eliminates unnecessary instructions;

Removes Tutorial information: obfuscate Androiddepuración code;

Renames classes, fields, and methods with unlegible names.

**DEXGUARD**

The enhanced commercial version of Proguard. This tool is capable of implementing the text encryption technique and renaming classes and methods with non-ASCII symbols.

#### Static analysis — Deobfuscation

[**Deguard**]
It is based on powerful probabilistic graphical models learned from thousands of open source programs. Using these models, Deguard retrieves important information in Android APK, including method and class names, as well as third-party libraries. Deguard can reveal string decoders and classes that handle sensitive data in Android malware.

By [Moataz Osama](https://medium.com/@mezo512) on [February 22, 2025](https://medium.com/p/ecbab20bca69).

[Canonical link](https://medium.com/@mezo512/android-hacking-part2-reverse-engineering-static-analysis-ecbab20bca69)

Exported from [Medium](https://medium.com) on August 26, 2025.