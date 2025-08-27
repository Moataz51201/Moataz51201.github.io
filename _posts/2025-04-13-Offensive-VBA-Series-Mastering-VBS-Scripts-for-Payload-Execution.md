---
layout: post
title: "Offensive VBA Series: Mastering VBS Scripts for Payload Execution"
date: 2025-08-26
categories: [Red Team,Macro,Malware Analysis,Malware Development,Blue Team,VBA,Cyber Security]
image: https://cdn-images-1.medium.com/max/800/1*3t0ECJO9kAYsWiRwW5FHqw.jpeg
---

### Introduction

Macro malware arrived with a bang 30 years ago, and it’s still causing problems. Concept, the first ever virus to spread by infecting Microsoft Office files, turned the anti-virus world on its head overnight when it was shipped by Microsoft on a CD ROM in August 1995. Up until then the main thing computer users had to worry about was malware hiding in .EXE or .COM executable files, or in the boot sectors of floppy disks. Now you had to be wary of Word documents too, and the risk was heightened when you recognized that exchanging documents in the office was a much more regular behavior than sharing executable code. It didn’t take long for macro viruses to become the most commonly-encountered type of malware on the planet

Visual Basic Script (VBS) has been a staple in Windows environments for decades, often used for automation, administrative tasks, and **malware development**. Cybercriminals and Red Teamers alike have leveraged VBS macros in **malicious Office documents, phishing attacks, and persistence techniques** to execute payloads stealthily.

Macros are written in Visual Basic for Applications (VBA) and are saved as part of the Office file. Macros are often created for legitimate reasons, but they can also be written by attackers to gain access to or harm a system, or to bypass other security controls such as application allow list.

In this **Malicious Macro Series**, we will break down **step-by-step techniques** used in offensive security, from basic scripting to advanced payload execution. Whether you’re an ethical hacker, penetration tester, or just curious about **how malware developers weaponize VBS**, this series will provide **hands-on** knowledge backed with real-world scenarios.

#### What You’ll Learn in This Series:

**1. VBS Basics:** Learn how to use `MsgBox`, `If-Else` conditions, loops, and functions to build fundamental scripts.  
**2. Command Execution:** Discover how VBS interacts with the Windows command line to execute system commands.

3\. **Encoded Dropper:** Hide and execute payloads in an obfuscated manner to evade antivirus detection.  
**4. PowerShell Dropper:** Leverage PowerShell within VBS to download and execute remote payloads.  
5\. **Auto-Remove Dropper:** Learn how malware authors create self-deleting scripts for stealthy execution.

We will start now with the basics.

* * *

#### Function Execution &amp; Message Box

```
Sub basicVBA()
    Dim result As Integer
    result = AddNumbers(10, 40)
    MsgBox "The sum is " & result, vbInformation, "Adding Numbers"
End Sub
```

#### Analysis:

- `Dim result As Integer` : Declares `result` as an **integer** (explicit typing).
- `result = AddNumbers(10, 40)` : Calls the `AddNumbers` function and stores the return value.
- `MsgBox "The sum is " & result, vbInformation, "Adding Numbers"`:**Concatenates** `"The sum is "` with `result` to form a message.
- Uses `vbInformation:`Adds an **information icon** in the message box.
- `"Adding Numbers" :`is the **title** of the message box.

#### Function for Addition

```
Function AddNumbers(a As Integer, b As Integer) As Integer
    AddNumbers = a + b
End Function
```

#### Analysis:

- This is a **function with a return type** (`Integer`).
- `AddNumbers = a + b`

**Assignment without** `Return`:

- In VBA, the function name itself **acts as a variable**, storing the return value.
- The last assignment before function termination is automatically returned.

#### Auto-Execution with `AutoOpen()`

```
Sub AutoOpen()
    Call basicVBA
End Sub
```

#### Analysis:

- `Sub AutoOpen()` : defines a **subroutine** (a function that doesn’t return a value).
- The `Call` keyword invokes the basicVBA function.

**Execution Flow:**

- Since `AutoOpen()` is a **reserved VBA macro**, it **automatically executes** when the document opens.
- This is often used in macros to trigger malicious payloads **without user interaction**.

![](https://cdn-images-1.medium.com/max/800/1*E6XiFHHj6Eqcb-QcUow3QA.png)

* * *

### Conditional Execution: `MsgBox` with User Input

```
Sub MessageWithButtons()
    Dim response As Integer
    response = MsgBox("Do you want to continue? ", vbYesNo + vbQuestion, "Confirmation")
    If response = vbYes Then
        MsgBox "You chose Yes!"
    Else
        MsgBox "You chose No!"
    End If
End Sub
```

#### Analysis:

- `Dim response As Integer` : Declares `response` variable.

`MsgBox("Do you want to continue?", vbYesNo + vbQuestion, "Confirmation"):`

- Uses `vbYesNo` to **display two buttons (**`Yes` **/** `No`**)**.
- Uses `vbQuestion` to **add a question mark icon**.
- Stores the button response (`vbYes` = 6, `vbNo` = 7).

**Control Flow (**`If-Else`**)**

**If** `response = vbYes` **(user clicked Yes)**

- Show **“You chose Yes!”** message.

**Else (user clicked No)**

- Show **“You chose No!”** message.

![](https://cdn-images-1.medium.com/max/600/1*-P3pnBpszYp2zMp6W-2E1Q.png)

![](https://cdn-images-1.medium.com/max/600/1*89BR-GvJbRa_GPa6td59Lw.png)

* * *

### Iterative Execution with a `For` Loop

```
Sub PrintNumbers()
    Dim i As Integer
    For i = 1 To 5
        MsgBox "Number: " & i
    Next i
End Sub
```

#### Analysis:

- `Dim i As Integer` : Declares loop counter `i`.

`For i = 1 To 5`

- Starts at `1`, increments by `1`, stops at `5`.

`MsgBox "Number: " & i`

- Displays `Number: 1`, `Number: 2`, ..., `Number: 5`.

![](https://cdn-images-1.medium.com/max/600/1*QZKIw6qOKZR4FUT_Tcfj2Q.png)

![](https://cdn-images-1.medium.com/max/600/1*QZKIw6qOKZR4FUT_Tcfj2Q.png)

* * *

### Command Execution using VBA

The `Shell` function in **Visual Basic for Applications (VBA)** is used to **run an external program or command** from within a script. It is commonly used to execute batch scripts, PowerShell commands, or executables.

* * *

#### Syntax

```
Shell(pathname, [windowstyle])
```

#### Arguments

ParameterDescription`pathname`**(Required)** The command line string or the full path of the executable you want to run.`windowstyle`**(Optional)** Determines how the window of the executed program appears (hidden, minimized, etc.).

#### WindowStyle Values

The `windowstyle` parameter is optional, but it allows you to control how the executed program's window behaves.

`vbHide, 0:`The window is hidden and does not appear in the taskbar.

`vbNormalFocus, 1:`Default. The window has focus and is restored to its original size and position.

`vbMinimizedFocus, 2:`The window is minimized but has focus.

`vbMaximizedFocus, 3:`The window is maximized with focus.

`vbNormalNoFocus, 4:`The window is restored to its most recent size and position but does not get focus.

`vbMinimizedNoFocus, 6`The window is minimized without focus.

* * *

#### 1. Executing a Command with `Shell()`

```
Sub RunCommand()
    Shell "cmd.exe /c echo Hello World! > C:\Users\Desktop\output.txt"
End Sub
```

#### How It Works:

`Shell("cmd.exe /c ...")`

- Launches the **Windows Command Prompt (**`cmd.exe`**)**.
- `/c` : Runs the command **and then terminates** the command prompt.

`echo Hello World! > C:\Users\Desktop\output.txt`

- `echo Hello World!` : Prints `"Hello World!"` to the output.
- `>` : Redirects output to **a file** (`output.txt`).
- The file is created at `C:\Users\Desktop\output.txt`.

* * *

#### 2. Running an Executable (`notepad.exe`) with Shell

```
Sub RunShell()
    Shell "notepad.exe", 0
End Sub
```

#### How It Works:

`Shell("notepad.exe", X)` launches **Notepad** with Hidden Mode.

- `0` : Hidden mode (stealth execution).

* * *

#### 3. Running Windows Scripts Using `WScript.Shell`

```
Sub winScript()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run("calc.exe")
End Sub
```

#### How It Works:

`Dim objShell As Object:`

- Declares `objShell` as a **generic Object** (late binding).

`Set objShell = CreateObject("WScript.Shell")`

- Uses **COM automation** to create a `WScript.Shell` instance.

`objShell.Run("calc.exe")`

- Executes **Calculator (**`calc.exe`**)**.

**Key Difference from** `Shell()`

- **Supports advanced execution** (e.g., waiting for a process, running as admin).
- Example:

> `objShell.Run "cmd.exe /c start malicious.bat", 0, True`

- Runs `malicious.bat` **in hidden mode** (`0`).
- `True` → **Waits for execution to finish** before continuing.

* * *

Now that we understand how commands are executed, let us combine them to create a sysinfo dumper.

#### `SystemInforDumper()`

This VBA macro retrieves **system information** from the Windows operating system using the `systeminfo` command and displays it in a message box.

#### 1. Declaring Variables

```
Dim objShell As Object
Dim execCmd As Object
Dim outputLine As String
Dim systemInfo As String
```

#### Explanation:

- `objShell:`Stores an instance of `WScript.Shell`, allowing us to execute system commands.
- `execCmd` : Stores the **command execution process**.
- `outputLine` : Temporarily holds **each line** of the command output.
- `systemInfo` : Stores the **entire system information** retrieved from the command.

#### 2. Creating a WScript.Shell Object

```
Set objShell = CreateObject("WScript.Shell")
```

- `CreateObject("WScript.Shell"):` creates a `WScript.Shell` instance, which allows interaction with the operating system.

#### 3. Executing the SystemInfo Command

```
Set execCmd = objShell.Exec("cmd.exe /c systeminfo")
```

- `objShell.Exec()` : Runs the **command** and returns an object that lets us **capture the output**.

`"cmd.exe /c systeminfo"`

- `cmd.exe` : Opens the **Command Prompt**.
- `/c` : Runs the command and **closes the Command Prompt** immediately after execution.

`systeminfo` : Retrieves detailed **system information** such as:

- OS Name, Version, Architecture
- CPU, RAM, Installed Hotfixes, and Network Info

**Why Use** `Exec()` **Instead of** `Run()`**?**

- `Run()` simply **executes** the command **without capturing** output.
- `Exec()` allows us to **read the command output** (needed in this case).

#### 4. Capturing the Command Output (Loop Processing)

```
Do While Not execCmd.StdOut.AtEndOfStream
    outputLine = execCmd.StdOut.ReadLine
    systemInfo = systemInfo & outputLine & vbCrLf
Loop
```

#### Step-by-Step Execution:

1. `execCmd.StdOut` : Captures the **command output** (`systeminfo` results).
2. **Loop Condition:**

<!--THE END-->

- `AtEndOfStream:` checks if there's **more output** to read.
- **Loop continues** until all output is read.

**Processing Each Line:**

- `outputLine = execCmd.StdOut.ReadLine` : reads **one line** from the output.

`systemInfo = systemInfo & outputLine & vbCrLf`

- **Concatenates** each line to `systemInfo`.
- `vbCrLf` : Adds a **new line** (`Carriage Return + Line Feed`).

* * *

#### 5. Displaying the Collected System Information

```
MsgBox systemInfo, vbInformation, "System Information"
```

- `MsgBox` : Displays the system info **in a message box**.
- `vbInformation` : Adds **an information icon**.
- `"System Information"` : Title of the message box.

![](https://cdn-images-1.medium.com/max/800/1*qKb89Bh_ZCcWRn3zXfvnLg.png)

* * *

This VBA script utilizes **PowerShell execution** to run commands and store outputs. The use of `WScript.Shell` allows macros to execute **system commands**, making it a potential **macro-based dropper** (i.e., a technique to execute malicious payloads via PowerShell).

#### 1. Understanding `RunPowerShell()`

```
Sub RunPowerShell()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -Command ""Get-Process | Out-File C:\Users\user\Desktop\out.txt""", 0 , True
End Sub
```

**Create** `WScript.Shell` **Object**

- `Set objShell = CreateObject("WScript.Shell")`
- This **creates an instance** of `WScript.Shell`, which is used to **execute PowerShell commands**.

**Execute PowerShell Command**

`objShell.Run "powershell.exe -Command ""Get-Process | Out-File C:\Users\user\Desktop\out.txt""", 0 , True`

- `powershell.exe -Command:`Executes a **PowerShell command**.
- `Get-Process` : Retrieves a list of **all running processes**.
- `Out-File C:\Users\user\Desktop\out.txt` : Saves the output to a text file.
- `0` : Runs in **hidden mode** (no PowerShell window).
- `True` : Runs **synchronously**, meaning the script waits for the process to complete before continuing.

#### 2. Understanding `inMemExec()` (In-Memory Execution)

```
Sub inMemExec()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""[System.Diagnostics.Process]::Start(notepad.exe)""" , 0, True
End Sub
```

#### Step-by-Step Execution

1. **Create** `WScript.Shell` **Object**

<!--THE END-->

- `Set objShell = CreateObject("WScript.Shell")`

> `objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""[System.Diagnostics.Process]::Start(notepad.exe)""" , 0, True`

- `powershell.exe` : Executes PowerShell.
- `-NoProfile` : Prevents loading the PowerShell profile (**faster execution, less detection**).
- `-ExecutionPolicy Bypass:`**Bypasses script execution restrictions**.

`[System.Diagnostics.Process]::Start("notepad.exe")`

- Uses **.NET’s System.Diagnostics** to launch Notepad.
- Executes **without spawning a PowerShell window** (**stealthier execution**).
- `0` : Runs in hidden mode.
- `True` : Runs synchronously.

* * *

### Next Steps in the Malicious Macro Series

Now that we’ve covered **VBA basics**, upcoming topics will explore:

1. **Encoded Droppers** (Payload delivery techniques)
2. **PowerShell Droppers** (Executing hidden commands)
3. **Auto-Removing Droppers** (Evading detection)

Stay tuned.

By [Moataz Osama](https://medium.com/@mezo512) on [April 13, 2025](https://medium.com/p/66b25e1b4bad).

[Canonical link](https://medium.com/@mezo512/offensive-vba-series-mastering-vbs-scripts-for-payload-execution-66b25e1b4bad)

Exported from [Medium](https://medium.com) on August 26, 2025.