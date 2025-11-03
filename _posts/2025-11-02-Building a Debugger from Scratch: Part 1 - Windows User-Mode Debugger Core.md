---
title: "Building a Debugger from Scratch: Part 1 - Windows User-Mode Debugger Core"
date: 2025-11-02  
categories: [Debugger]
tags: [Debugger]
image: "https://i.pinimg.com/1200x/2c/14/1c/2c141ce3c05039619b6dca4a3ab43fbe.jpg"
---

In this Part 1, we will build the Core of a Windows Debugger: Process Creation, Attach/Detach, Event Loop, and Privilege Management

![alt text](/assets/post8/deamon_eye.png)

## Anatomy of dbg_create_process: Creating Processes in Debug Mode
This function will be essential in creating our debugger; let's dissect it and understand its behavior line by line:
```c
int dbg_create_process(const char *path, const char *args, PROCESS_INFORMATION *pi_out) {
    if (!path || !pi_out) return -1;
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(pi_out, sizeof(*pi_out));

    char cmdline[4096];
    if (args && args[0]) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", path, args);
    } else {
        snprintf(cmdline, sizeof(cmdline), "\"%s\"", path);
    }

    DWORD creationFlags = DEBUG_ONLY_THIS_PROCESS; 
    BOOL ok = CreateProcessA(
        NULL,               // lpApplicationName
        cmdline,            // lpCommandLine  
        NULL,               // lpProcessAttributes
        NULL,               // lpThreadAttributes
        FALSE,              // bInheritHandles
        creationFlags,      // dwCreationFlags ← DEBUG_ONLY_THIS_PROCESS
        NULL,               // lpEnvironment
        NULL,               // lpCurrentDirectory
        &si,
        pi_out
    );
    if (!ok) {
        print_last_error("CreateProcessA");
        return -2;
    }

    g_pi = *pi_out;
    g_hProcess = pi_out->hProcess;
    g_debuggee_pid = pi_out->dwProcessId;

    return 0;
}
```
### Initial Validation
```c
int dbg_create_process(const char *path, const char *args, PROCESS_INFORMATION *pi_out)
```
In the function signature, we have three essential parameters.
path represents the path to the executable that the debugger will open, something like "C:\\Windows\\...\\notepad.exe", that is, the path to some executable binary.
*pi_out is a pointer to a PROCESS_INFORMATION structure where Windows will return all critical information about the created process.

```c
if (!path || !pi_out) return -1;
```
A safety check, if either path or pi_out is null, the function immediately returns with error -1. This validation is essential against null pointer exceptions that could crash our debugger before it even starts working.

## Structure Initialization
```c
STARTUPINFOA si;
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(pi_out, sizeof(*pi_out));
```
Here we enter the initialization of Windows structures.
STARTUPINFOA is a struct that defines how the process itself will be started.
ZeroMemory completely clears the structure, ensuring there’s no garbage memory that could interfere with the process.An important field we set is si.cb = sizeof(si), a mandatory field so that Windows can identify the version of the structure being used, without it, the API would fail.

### Preparação de linha de comando
```c
char cmdline[4096];
if (args && args[0]) {
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", path, args);
} else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", path);
}
```
Here we create a buffer called cmdline that holds 4096 bytes to accommodate long paths and multiple arguments. An important logic is implemented here: if args is not null and not empty, we format the string as ""%s" %s"" this puts the path in quotes (essential for paths with spaces) followed by the arguments. If there are no arguments, we use "%s" around the path.
This approach with quotes is vital because it protects paths like "C:\Program Files\my app\app.exe" that contain spaces.
We must be careful with the command line because the CreateProcessA function can modify the contents of the buffer we pass to cmdline.

### CreateProcessA

```c
DWORD creationFlags = DEBUG_ONLY_THIS_PROCESS; 
BOOL ok = CreateProcessA(
    NULL,               
    cmdline,            
    NULL,               
    NULL,               
    FALSE,              
    creationFlags,      // DEBUG_ONLY_THIS_PROCESS 
    NULL,               
    NULL,               
    &si,                
    pi_out              
);
```
Here we reach the main part of our function, the call to CreateProcessA.
The most important parameter here is creationFlags, where we pass DEBUG_ONLY_THIS_PROCESS.
This single flag is what transforms a normal process creation into a complete debugging session.

#### Understanding Each Parameter in This Call
The first parameter is NULL, indicating that we want to use cmdline instead of a separate application name, cmdline contains our formatted string with path and arguments.
The next two NULLs define the process and thread security attributes as default and FALSE for bInheritHandles means that the child process will not inherit handles from our debugger.

Then comes the main flag: DEBUG_ONLY_THIS_PROCESS. When DEBUG_ONLY_THIS_PROCESS is present, Windows creates the process normally but attaches it to a debugging session.
The system will generate initial events that the debugger must consume.
The user execution is implicitly held until the debugger handles and allows continuation via ContinueDebugEvent.

### Global Storage
```c
g_pi = *pi_out;
g_hProcess = pi_out->hProcess;
g_debuggee_pid = pi_out->dwProcessId;
```
When creating the process, we store its information globally in g_pi, g_hProcess, and g_debuggee_pid. This global storage is essential because other parts of the debugger, such as the event loop, breakpoint commands, and memory reading functions, need access to these structures to maintain a clean and consistent integration with the debuggee process.

### dbg_debug_loop_thread
Now let’s analyze the dbg_debug_loop_thread function, which is a core component in the construction of our debugger.
It runs in a separate thread and is responsible for processing all events that occur within the process being debugged.

![alt text](https://i.pinimg.com/736x/72/a3/3a/72a33a075849ed039e5bb7e10307428e.jpg)

```c
unsigned __stdcall dbg_debug_loop_thread(void *arg) {
    (void)arg;
    DEBUG_EVENT dbgEvent;
    DWORD waitMs = 500; 
    g_debug_thread_running = true;
    g_terminate_debug_thread = false;
    fprintf(stdout, "[debugger] debug loop started (pid=%u)\n", (unsigned)g_debuggee_pid);

    while (!g_terminate_debug_thread) {
        BOOL have = WaitForDebugEvent(&dbgEvent, waitMs);
        if (!have) {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT || err == WAIT_TIMEOUT) {
                continue;
            } else {
                continue;
            }
        }
        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT:
            fprintf(stdout, "[event] CREATE_PROCESS pid=%u tid=%u base=%p\n",
                (unsigned)dbgEvent.dwProcessId, (unsigned)dbgEvent.dwThreadId,
                dbgEvent.u.CreateProcessInfo.lpBaseOfImage);

            if (!g_hProcess && dbgEvent.u.CreateProcessInfo.hProcess) {
                g_hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
                g_debuggee_pid = dbgEvent.dwProcessId;
            }

            dbg_thread_add(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);

            if (dbgEvent.u.CreateProcessInfo.hFile)
                CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);

            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            fprintf(stdout, "[event] EXIT_PROCESS pid=%u exitcode=%u\n",
                (unsigned)dbgEvent.dwProcessId,
                (unsigned)dbgEvent.u.ExitProcess.dwExitCode);
            g_terminate_debug_thread = true;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            fprintf(stdout, "[event] CREATE_THREAD tid=%u start=%p\n",
                (unsigned)dbgEvent.dwThreadId,
                dbgEvent.u.CreateThread.lpStartAddress);
            dbg_thread_add(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            fprintf(stdout, "[event] EXIT_THREAD tid=%u exit=%u\n",
                (unsigned)dbgEvent.dwThreadId,
                (unsigned)dbgEvent.u.ExitThread.dwExitCode);
            dbg_thread_remove(dbgEvent.dwThreadId);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            fprintf(stdout, "[event] LOAD_DLL base=%p handle=%p\n",
                dbgEvent.u.LoadDll.lpBaseOfDll,
                dbgEvent.u.LoadDll.hFile);
            if (dbgEvent.u.LoadDll.hFile)
                CloseHandle(dbgEvent.u.LoadDll.hFile);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            fprintf(stdout, "[event] OUTPUT_DEBUG_STRING\n");
            break;

        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
            PVOID addr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

            fprintf(stdout, "[event] EXCEPTION pid=%u tid=%u code=0x%08X addr=%p first-chance=%d\n",
                (unsigned)dbgEvent.dwProcessId,
                (unsigned)dbgEvent.dwThreadId,
                (unsigned)code, addr,
                (int)dbgEvent.u.Exception.dwFirstChance);

            switch (code) {
            case EXCEPTION_BREAKPOINT:
                fprintf(stdout, "  -> BREAKPOINT hit at %p (tid=%u)\n",
                    addr, (unsigned)dbgEvent.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;

            case EXCEPTION_SINGLE_STEP:
                fprintf(stdout, "  -> SINGLE_STEP (tid=%u)\n",
                    (unsigned)dbgEvent.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;

            default:
                if (dbgEvent.u.Exception.dwFirstChance) {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                } else {
                    fprintf(stdout, "  -> UNHANDLED EXCEPTION (second-chance)\n");
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            }
            break;
        }

        default:
            fprintf(stdout, "[event] UNKNOWN (%u)\n", dbgEvent.dwDebugEventCode);
            break;
        }
        if (!ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus)) {
            print_last_error("ContinueDebugEvent");
        }
    }

    fprintf(stdout, "[debugger] debug loop exiting\n");
    g_debug_thread_running = false;
    return 0;
}
```

### Initialization
```c
DEBUG_EVENT dbgEvent;
    DWORD waitMs = 500; 
    g_debug_thread_running = true;
    g_terminate_debug_thread = false;
    fprintf(stdout, "[debugger] debug loop started (pid=%u)\n", (unsigned)g_debuggee_pid);
```
The first thing this function does is initialize its local variables and the global state.
We create a DEBUG_EVENT dbgEvent structure, which will be filled by Windows with information about each debugging event. The line DWORD waitMs = 500 defines a half-second timeout for waiting on debug events.

Next, we set the global flags:
g_debug_thread_running = true indicates that the debug loop is active,
while g_terminate_debug_thread = false allows the loop to continue running until an explicit termination request is made.

### Main Loop
```c
while (!g_terminate_debug_thread) {
        BOOL have = WaitForDebugEvent(&dbgEvent, waitMs);
        if (!have) {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT || err == WAIT_TIMEOUT) {
                continue;
            } else {
                continue;
            }
        }
    ....
```
Entering the main loop of the function with while (!g_terminate_debug_thread).
This condition ensures that the loop can be gracefully terminated from other parts of the program, for instance, when the user types "quit" in the CLI or when the debuggee process exits.

Inside the loop, the most important call is WaitForDebugEvent(&dbgEvent, waitMs).
This Windows API function is blocking, but thanks to our 500 ms timeout, it returns even when no events occur, allowing us to periodically check whether the loop should terminate. If WaitForDebugEvent returns FALSE, we move into the error handling section.
Here, we check if the error was a normal timeout (ERROR_SEM_TIMEOUT or WAIT_TIMEOUT).
If that’s the case, we simply continue the loop without interruption.

```c
        DWORD continueStatus = DBG_CONTINUE;
```
When a valid event is received, we initialize the variable with a default value, this variable determines how the event will be continued once processing is complete.

### Main code block of the function

```c
switch (dbgEvent.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT:
            fprintf(stdout, "[event] CREATE_PROCESS pid=%u tid=%u base=%p\n",
                (unsigned)dbgEvent.dwProcessId, (unsigned)dbgEvent.dwThreadId,
                dbgEvent.u.CreateProcessInfo.lpBaseOfImage);

            if (!g_hProcess && dbgEvent.u.CreateProcessInfo.hProcess) {
                g_hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
                g_debuggee_pid = dbgEvent.dwProcessId;
            }

            dbg_thread_add(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);

            if (dbgEvent.u.CreateProcessInfo.hFile)
                CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);

            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            fprintf(stdout, "[event] EXIT_PROCESS pid=%u exitcode=%u\n",
                (unsigned)dbgEvent.dwProcessId,
                (unsigned)dbgEvent.u.ExitProcess.dwExitCode);
            g_terminate_debug_thread = true;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            fprintf(stdout, "[event] CREATE_THREAD tid=%u start=%p\n",
                (unsigned)dbgEvent.dwThreadId,
                dbgEvent.u.CreateThread.lpStartAddress);
            dbg_thread_add(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            fprintf(stdout, "[event] EXIT_THREAD tid=%u exit=%u\n",
                (unsigned)dbgEvent.dwThreadId,
                (unsigned)dbgEvent.u.ExitThread.dwExitCode);
            dbg_thread_remove(dbgEvent.dwThreadId);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            fprintf(stdout, "[event] LOAD_DLL base=%p handle=%p\n",
                dbgEvent.u.LoadDll.lpBaseOfDll,
                dbgEvent.u.LoadDll.hFile);
            if (dbgEvent.u.LoadDll.hFile)
                CloseHandle(dbgEvent.u.LoadDll.hFile);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            fprintf(stdout, "[event] OUTPUT_DEBUG_STRING\n");
            break;

        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
            PVOID addr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

            fprintf(stdout, "[event] EXCEPTION pid=%u tid=%u code=0x%08X addr=%p first-chance=%d\n",
                (unsigned)dbgEvent.dwProcessId,
                (unsigned)dbgEvent.dwThreadId,
                (unsigned)code, addr,
                (int)dbgEvent.u.Exception.dwFirstChance);

            switch (code) {
            case EXCEPTION_BREAKPOINT:
                fprintf(stdout, "  -> BREAKPOINT hit at %p (tid=%u)\n",
                    addr, (unsigned)dbgEvent.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;

            case EXCEPTION_SINGLE_STEP:
                fprintf(stdout, "  -> SINGLE_STEP (tid=%u)\n",
                    (unsigned)dbgEvent.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;

            default:
                if (dbgEvent.u.Exception.dwFirstChance) {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                } else {
                    fprintf(stdout, "  -> UNHANDLED EXCEPTION (second-chance)\n");
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            }
            break;
        }
```
Here we reach the main switch statement that processes the different types of debug events.
Each case handles a specific kind of event that can occur during runtime.

The CREATE_PROCESS_DEBUG_EVENT is the primitive event received when a process is created in debug mode. At this point, we set information such as the PID, TID, and the base address where the executable was loaded. We also store the process handle globally if it hasn’t already been set.

#### CREATE_THREAD_DEBUG_EVENT and EXIT_THREAD_DEBUG_EVENT
The CREATE_THREAD_DEBUG_EVENT and EXIT_THREAD_DEBUG_EVENT manage the lifecycle of threads.
Whenever a new thread is created within the process, we receive a creation event and add it to our list; when it terminates, we remove it.

#### LOAD_DLL_DEBUG_EVENT
Basically, it notifies us when a DLL is loaded into the process. We log the base address where the DLL was loaded and once again close the handle.

#### OUTPUT_DEBUG_STRING_EVENT and EXCEPTION_DEBUG_EVENT 
The OUTPUT_DEBUG_STRING_EVENT happens when the debuggee process calls OutputDebugString. Maybe in the future, we could read and display the actual string, but for now, we just log the event occurrence.

And the EXCEPTION_DEBUG_EVENT is more complex since it deals with all the exceptions that occur in the debuggee process.
Within the exceptions, we handle two special cases: EXCEPTION_BREAKPOINT and EXCEPTION_SINGLE_STEP. These are exceptions that are part of the normal debugging process; for both, we use continueStatus = DBG_CONTINUE to indicate that the debugger has handled them.

For other exceptions, the logic is more subtle. If it is a "first-chance" exception (dwFirstChance true), we use DBG_EXCEPTION_NOT_HANDLED to allow the debuggee process to try to handle the exception through its own handlers. If it is "second-chance" (meaning the process could not handle the exception), we also use DBG_EXCEPTION_NOT_HANDLED, but log that it is an unhandled exception.

### ContinueDebugEvent
Finally, after processing each event, we call ContinueDebugEvent with the appropriate PID, TID, and continueStatus, as this call is fundamental; without it, the process would remain permanently suspended.

![alt text](https://i.pinimg.com/736x/54/80/72/5480729d7503553bef3c1066bbf6a63c.jpg)

## dbg_attach_process function

```c
int dbg_attach_process(DWORD pid, HANDLE *hProcessOut) {
    if (pid == 0) return -1;
    if (!DebugActiveProcess(pid)) {
        print_last_error("DebugActiveProcess");
        return -2;
    }
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        print_last_error("OpenProcess");
        return -3;
    }
    if (hProcessOut) *hProcessOut = hProc;
    g_hProcess = hProc;
    g_debuggee_pid = pid;
    return 0;
}
```
This function is designed to connect to processes that are already running. It already starts with a fundamental check, rejecting PIDs set to zero, which belong to the System Idle Process and never represent a valid user process. Then, it calls the API DebugActiveProcess, which according to [Microsoft`s documentation](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess) “enables a debugger to attach to an active process and debug it.” Then Windows suspends all the threads of the process and starts sending debug events to our application.

### PROCESS_ALL_ACESS
```c
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        print_last_error("OpenProcess");
        return -3;
    }
```

For everything to work properly, we need a handle with full access to the process for future operations such as memory reading and breakpoint configuration. That’s why we call OpenProcess with PROCESS_ALL_ACCESS, ensuring that we will have full control over the process.

## dbg_detach_process
```c
int dbg_detach_process(DWORD pid) {
    if (pid == 0) return -1;
    if (!DebugActiveProcessStop(pid)) {
        print_last_error("DebugActiveProcessStop");
        return -2;
    }
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    g_debuggee_pid = 0;
    return 0;
}
```
The function dbg_detach_process represents the termination of the debugging session for a given process. This function begins with a PID validation: if (pid == 0) return;, which protects against attempts to detach from non-existent processes.
The main call is the DebugActiveProcessStop(pid) API, this Windows API is the counterpart of DebugActiveProcess, as it terminates the relationship between the process and the debugger, returning the process to its normal execution state if successful.
After this call, a resource cleanup process is initiated with the following code snippet:
```c
if (g_hProcess) { CloseHandle(g_hProcess); g_hProcess = NULL; }
```
This closes the handle of the previous process, which is good practice since every active handle consumes kernel memory.

![alt image](https://i.pinimg.com/736x/31/49/9e/31499e4671ce18489e9d5c78fb5e8b2d.jpg)

## enable_debug_privilege
```c
int dbg_enable_debug_privilege(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        print_last_error("OpenProcessToken");
        return -1;
    }
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        print_last_error("LookupPrivilegeValue");
        CloseHandle(hToken);
        return -2;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        print_last_error("AdjustTokenPrivileges");
        CloseHandle(hToken);
        return -3;
    }
    CloseHandle(hToken);
    return 0;
}
```
This function is responsible for enabling the SE_DEBUG_PRIVILEGE, a special capability that allows our process to access and debug other processes with elevated security levels.
```c
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken).
```
This call obtains a handle to the access token of our process. The token is essentially a Windows security structure that contains all permissions and privileges associated with the process. We always need TOKEN_ADJUST_PRIVILEGES to modify privileges and TOKEN_QUERY to read their current state. 
With the token in hand, we proceed to:
```c
 LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid)
```
The LUID is basically a numeric identifier used internally by the system to represent each privilege. "SeDebugPrivilege" is the well-known name for the privilege that allows debugging of any process in the system, including protected or other-user processes.

The main operation occurs in:
```c
AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)
```
This API effectively applies our privilege changes to the process token. The FALSE parameter for DisableAllPrivileges indicates that we only want to modify the specific privilege we provided, keeping all others untouched.
Finally, we close the token handle with CloseHandle(hToken) to avoid system resource leaks.
It’s worth noting that enabling SE_DEBUG_PRIVILEGE is not a trivial operation, it often requires the process to be run with elevated privileges (as Administrator) or that the user account already possesses this privilege.

![alt image](https://i.pinimg.com/736x/24/94/21/249421f9be85c3865eb87877181e79f8.jpg)

## Part 2 coming soon...
With these fundamental building blocks implemented, we have a functional debugger kernel capable of process control and event handling. In the next part, we’ll expand its capabilities with breakpoint management, memory inspection, and a richer CLI.