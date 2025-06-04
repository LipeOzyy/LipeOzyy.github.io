---
title: "Building and Detecting a Backdoor: Dynamic Analysis and YARA Rules"
date: 2025-06-03    
categories: [Malware]
tags: [Malware]
image: "https://i.pinimg.com/736x/d3/f7/41/d3f741e990333aabdd7bee363a0c94d4.jpg"
---

# Building and Detecting a Backdoor: Dynamic Analysis and YARA Rules


This article aims to demonstrate how YARA rules can be used to detect backdoors by combining strong indicator: the presence of Windows networking API calls commonly found in malware routines. The goal of this post is to create a backdoor in C, analyze the compiled binary, and write a YARA rule for it, using malware development and reverse engineering techniques.

## Part 1 — Coding a Simple Backdoor in C Using Windows API Calls
To build our backdoor, we’ll use the following libraries:

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*u7APEWcLxsVyl-kuykhUyg.png)

Now, the backdoor starts by loading the Winsock library using WSAStartup(), which is needed for network communication on Windows. Then it creates a TCP socket and sets the remote server info (IP and port) using the sockaddr_in structure. If any of these steps fail, the program simply exits.

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*i-pVEv3Xx3VFH440fqzrog.png)

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*66zY01u0aQBFIBRufVNwlw.png)

The CreateProcess() function is used to run cmd, creating a remote shell.

This is a simple example I coded. In a real world scenario, it’s not very effective since it has no persistence or evasion techniques. But that’s not the goal of this post, maybe I’ll publish something about that in the future.

After compiling our code and setting up Netcat listening on the defined port, we run the backdoor:

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*hkB-ezWaDjblljxtzojyNQ.png)

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*vhPlK-DdsfP3188X1Ug35Q.png)

Alright, our backdoor is working perfectly. Now let’s move on to analyzing the binary to create the YARA rules.

## Part 2- Analyzing and understanding the behavior of the executable through the debugger

Now, with our example backdoor executable ready, we are going to debug the binary to understand its behavior through dynamic analysis. To make this possible, I will once again leave my netcat listening on the port, so we can understand at which moment the connection is made, and then create the YARA rule.

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*h7zcyy6iD0eAeoHGGNcrLA.png)

First, I will set a breakpoint at the Entry Point, which leads me to the main function. From there, I can analyze the APIs being called during the execution of the main function.

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*sJX3UKqyvwDpVdTVDNTdrg.png)

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*KA5WsQrh7RkL1FvjVBXBuQ.png)

While analyzing the binary, I checked the imported functions. Through the ‘Imports’ tab, you can see which libraries and functions the executable uses at runtime. In my case, I noticed the binary makes use of several functions from the ws2_32.dll library, which handles network communication on Windows. The functions I found were:

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*OVc6G0JlenlV0MREUFT2Vw.png)

The combined use of these APIs is not common in legitimate software unless it performs specific networking functions. However, when this is associated with other suspicious behaviors, such as the execution of cmd.exe (which may indicate the creation of a remote shell) it becomes a strong indicator of malicious activity

## Part 3- Creating a YARA Rule Based on Imports and Strings:
After identifying the API calls in the binary and analyzing the strings to avoid false positives, I created a YARA rule based on that information.

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*vh2fkLH9ELBgptx0DLNpqg.png)

Testing our rule directly on the malicious executable to see if it triggers a detection:

![alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*LtbVjIeMtO5SxHEm8cO41g.png)

Due to the condition, no false positives were triggered.

As a result, we successfully achieved detection of the backdoor through thorough binary analysis, identifying suspicious API calls, relevant strings, and crafting a YARA rule based on these indicators. This process highlights how static analysis can be an effective approach to detect and mitigate malware threats.

## Here is a video I published demonstrating its functionality:

[Assista no YouTube](https://www.youtube.com/watch?v=_m_wSDVnYFE)

