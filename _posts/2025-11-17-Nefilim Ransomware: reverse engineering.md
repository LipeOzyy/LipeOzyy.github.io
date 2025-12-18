---
title: "Nefilim Ransomware: Reverse Engineering"
date: 2025-11-15
categories: [Malware]
tags: [Assembly, Nefilim, Malware, Reverse Engineering]
image: "https://i.pinimg.com/originals/eb/7f/0c/eb7f0ccf927c93aeedbb3cf100d6fd29.gif"
---

In this post, I will present an analysis of the Nefilim ransomware with as much detail as possible. I will try to explain the techniques used and what happens inside each function of the code. Later on, I will create a YARA rule for this malware.

----

## Static Analysis:
We will start by performing a complete and in-depth static analysis of the binary. First, I will analyze it using tools such as DIE, PEstudio, and PEbear. After that, we will move to the code itself using IDA, allowing us to understand more precisely what this ransomware does and how it does it.

### PEstudio Analysis
I loaded the binary into PEstudio to begin the analysis. The first thing I checked was the number of detections on VirusTotal:
![alt text](/assets/POST_10/vt_pe.png)
Since this is a well-known and somewhat old sample, it was expected to have a high number of signature-based detections. We can also confirm that it is indeed ransomware.
Next, I analyzed the libraries and imports used by the binary and obtained the following result:
![alt text](/assets/POST_10/libs.png)
[KERNEL32.dll](https://www.geoffchappell.com/studies/windows/win32/kernel32/api/index.htm) is probably the most important library here, as it contains low-level functions that manage memory and hardware, and also provides the ability to create processes and threads. The fact that Nefilim uses 76 imports from it (the highest number) indicates that it performs a large number of critical operations, such as data manipulation and direct interaction with the system kernel.

#### Strings
The strings section contains very interesting data:

![alt text](/assets/POST_10/strings_black_list.png)

Dude, this already reveals a lot about the behavior of the sample, even before looking at the code. What stands out are the multiple OCSP addresses, all belonging to certificate authorities such as DigiCert. This is quite typical of malware that attempts to validate certificates, or more commonly, tries to make its connections appear legitimate. In some cases, this may simply be leftover noise from a library included in the build. In other situations, it can act as cover noise.

Another interesting detail is that the malware’s focus on cryptography, hashing, and key manipulation is clearly exposed. Crypto-related imports appear in the strings, such as CryptHashData, CryptDecrypt, CryptDeriveKey, CryptEncrypt, CryptImportKey, and CryptAcquireContext.

There are also details that reveal even more, such as the presence of ShellExecute, which may indicate that the malware will execute something externally at some point, possibly for persistence. We will confirm this later.

Another string that caught my attention was the following:
```
ascii,1128,0x0000A9E0,-,P28bYetqAjMJwFdCu5KwgN5PGwkVckpRko+dpaPjLO7ofFiQDbKw8ovNbVTREf1xBQ6glzyU76V79uTCpaWeKoTIK27f4cF8GbrTFtiCBEPGFKlFUa9xOFxA/8iU3vp7QOYlJc6pPmGT0Z/MFnQhE0CqYav+ZfHo60djvhkjRBtoPLUcpUQ5jkOczEZPbghBDMjFVM/YFb49N687qDVvrBkiWsz2ehCWS0SMxVMJi4dpMwTc3FybPQPE73FBRFUS/aAHGjcQuSxMlzvAB7CqiEVjpFUodQwjRe7vkyt30HhFnEZmjqwbGTJea2tQ4jZ6AxIekd1brjxQuiQm+gmfc8Ic8zUBwuJgqvtZ0Nq1bPcEjakY2CI5cc+S4LZUTPU6njhVyVHifOH/tSn9IrD9jX6AODDD2jrQx4iVeZ4MnziKWlmcp9/WEgfmLGhGd0kAlpyXbJgBvjIAtvkdiSfyXnWtQSpqO0aLHIoBU+zfOTAOrSoFUEIRoEGYgVLK+/m93c90kSoa7Rkg81aBOat56uFM6j+6KE8TNIXLNK0ikPR9qX104J5xlpdGPPHuzZNOkoSAgw/ZZ2/qXRyCs8GU/ZyIY0/tNXj+E6pjeaxTHiRM3d+edqcmpxWBZOJjeBtztOlYUIw5J3hquaqNH6tkfF7e0XSEBeGAo3TdSlb4U3W+jlnzB8quhIzreGJ9Vh6Z4auZkWFejxeHLKXkB0xnpep5hJzXNPuFHT/PUwCrj8NOgc+usnDxxvK2yEWYx0Q2C5IChW+jIQb9+fYF7JavseSGl/JCuj9Or1UHrOUttk8YpIRlH9waaXD5kZpI6d2oSHAsQB1zhnRbb173T7ebR9+/22ttbaAV2KfVUo1kbfsWTHkg1dqquE84FoWApIwzwKZCmiY4MBVaAv2OasHLQp5boQFLyBzJv5+IdI9Pp/+sB9v2c0ssPO2NQ3R1mdYOdAOkh0QaH+BvuMPZPyfq14K05QmahmvUN6x5z6Z8LQGK2XMC7DNvVK0kWeTu2vJiWqNGUIOjH/SdldhPFbTWY+15dZC54nP267DtsRhZrdWl7FqWfgc0meAvHV2YHSa1g59qa98+O227TC9+5i1PVqyuEU1XO+7DZ1eLoNQ2
```
Its size, character set, and lack of human-readable content strongly indicate that it represents encoded binary data rather than plain text. Considering its proximity to cryptographic routines and the extensive use of the Windows CryptoAPI, it is highly likely that this blob is used as cryptographic material, such as a seed, key-related data, or an encrypted configuration block.

Embedding cryptographic data in this format is a common technique among ransomware families, as it hinders static analysis and prevents the direct exposure of sensitive information in a readable form.

### Entry point
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  HANDLE MutexA; // eax
  _BYTE *v4; // eax
  _DWORD *v5; // ecx
  _BYTE *v6; // esi
  _BYTE *v7; // ecx
  int v8; // eax
  char v9; // bl
  LPCWSTR v10[10]; // [esp-1Ch] [ebp-68h] BYREF
  const char **v11; // [esp+Ch] [ebp-40h]
  _BYTE v12[28]; // [esp+10h] [ebp-3Ch] BYREF
  _DWORD v13[4]; // [esp+2Ch] [ebp-20h] BYREF
  unsigned int v14; // [esp+3Ch] [ebp-10h]
  unsigned int v15; // [esp+40h] [ebp-Ch]

  v11 = argv;
  MutexA = CreateMutexA(0, 0, "Den'gi plyvut v karmany rekoy. My khodim po krayu nozha...");
  WaitForSingleObject(MutexA, 0);
  if ( GetLastError() == 183 )
    ExitThread(0);
  sub_402EFC();
  sub_402190((wchar_t *)L"NEFILIM");
  v4 = operator new[](v14);
  v5 = (_DWORD *)v13[0];
  lpBuffer = v4;
  if ( v15 < 8 )
    v5 = v13;
  v6 = (char *)v5 + 2 * v14;
  v7 = (_BYTE *)v13[0];
  if ( v15 < 8 )
    v7 = v13;
  while ( v7 != v6 )
  {
    *v4++ = *v7;
    v7 += 2;
  }
  nNumberOfBytesToWrite = v14;
  sub_4022DB(1);
  sub_402B29();
  if ( argc == 2 )
  {
    sub_402166((char *)argv[1]);
    v8 = sub_402FF0(v12);
    if ( *(_DWORD *)(v8 + 20) >= 8u )
      v8 = *(_DWORD *)v8;
    v9 = -PathIsDirectoryW((LPCWSTR)v8);
    sub_4022DB(1);
    sub_4021BE(1);
    sub_402166((char *)v11[1]);
    if ( v9 == -1 )
    {
      sub_402FF0(v12);
      v11 = (const char **)v10;
      wcslen(L"\\");
      sub_402A91((void *)L"\\");
      sub_4029A5();
      sub_401509((char)v10[0]);
      sub_4022DB(1);
    }
    else
    {
      sub_402FF0(v10);
      sub_401B93(v10[0], (int)v10[1], (int)v10[2], (int)v10[3], (int)v10[4], (int)v10[5]);
    }
    sub_4021BE(1);
    sub_402BD2();
  }
  else
  {
    sub_40206A();
    sub_402BD2();
    sub_402C32();
  }
  ExitProcess(0);
}
```
The first thing that caught my attention in the main function was the creation of a mutex with a very peculiar name:
```
"Den'gi plyvut v karmany rekoy. My khodim po krayu nozha..."
```
Translated from Russian, it means:
```
"Money is pouring into our pockets like a river. We're walking on a knife's edge..."
```
Quite philosophical, I would say. But since our goal here is not to discuss Nietzsche, let’s understand what is being created. A mutex is essentially a [Windows Synchronization Objects](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-objects) that can be used to control the execution of a payload.

A synchronization object is a kernel-provided programming primitive used to control access to a shared resource by multiple processes or threads operating concurrently. In other words, this mutex prevents two instances of the malware from running at the same time. If the mutex already exists (GetLastError() == 183), the process exits immediately, avoiding conflicts between instances.

Next, the malware makes two calls: first to sub_402EFC(), and then to sub_402190(L"NEFILIM"). We will analyze these functions in more detail later. After that, there is a somewhat confusing section:
```c
v4 = operator new[](v14);
...
while ( v7 != v6 )
{
    *v4++ = *v7;
    v7 += 2;
}
``` 
Overall, this looks like a data pre-processing phase before a heavier routine, such as encryption or directory traversal. For now, we will skip it.

### sub_402EFC() 
```c
int sub_402EFC()
{
  BYTE *v0; // edi
  _DWORD *v1; // eax
  _BYTE *v2; // esi
  _BYTE *v3; // eax
  int v4; // ecx
  _DWORD v6[4]; // [esp+Ch] [ebp-20h] BYREF
  DWORD dwDataLen; // [esp+1Ch] [ebp-10h]
  unsigned int v8; // [esp+20h] [ebp-Ch]

  if ( !CryptAcquireContextA(&phProv, 0, 0, 1u, 0xF0000000) )
    goto LABEL_2;
  sub_402166("ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'");
  v0 = (BYTE *)operator new[](dwDataLen);
  v1 = (_DWORD *)v6[0];
  if ( v8 < 0x10 )
    v1 = v6;
  v2 = (char *)v1 + dwDataLen;
  v3 = (_BYTE *)v6[0];
  if ( v8 < 0x10 )
    v3 = v6;
  if ( v3 != v2 )
  {
    v4 = v0 - v3;
    do
    {
      v3[v4] = *v3;
      ++v3;
    }
    while ( v3 != v2 );
  }
  if ( !CryptCreateHash(phProv, 0x8004u, 0, 0, &hBaseData)
    || !CryptHashData(hBaseData, v0, dwDataLen, 0)
    || !CryptDeriveKey(phProv, 0x6801u, hBaseData, 1u, &hKey) )
  {
LABEL_2:
    ExitProcess(0);
  }
  operator delete[](v0);
  return sub_4021BE(1);
}
```
When entering the sub_402EFC() function, which is the first one called inside main(), we can immediately observe that the malware attempts to obtain a cryptographic provider via [CryptAcquireContextA](https://learn.microsoft.com/pt-br/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta). According to the documentation:
```
The CryptAcquireContext function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). This handle is then used in calls to CryptoAPI functions that use the selected CSP.
```
If this API call fails, the process is terminated immediately. After that, the function sub_402166 is called, accompanied by another Russian phrase:
```
"ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'"
```
Which translates to:
```
“I feel pain somewhere in my chest, and the wounds in my heart will not heal.”
```
I was curious about these phrases and decided to do some quick research to see if they came from a book, song, or poem. However, they appear to originate from the Nefilim authors themselves.

Next, the code allocates a buffer (operator new[], with dwDataLen) and uses data stored inside the v6 structure. Once the buffer is ready, the most important part of this function begins. The malware attempts to create a hash using [CryptCreateHash](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash) with algorithm identifier 0x8004, which corresponds to SHA-1. It then feeds this hash with the contents of the buffer using [CryptHashData](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata) Finally, it derives a cryptographic key from this hash using [CryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey) with identifier 0x6801, which is commonly associated with AES in the Windows CryptoAPI.

At this point, there is not much more to say: the malware is simply transforming that initial block of data into an internal cryptographic key that will be used later.

## YARA Rule Creation

Based on the static analysis performed throughout this article, it is possible to identify a set of stable and highly characteristic artifacts associated with the Nefilim ransomware. These indicators go beyond generic strings or isolated API calls and reflect both behavioral and implementation-specific aspects of the malware.

One of the strongest indicators is the mutex created during execution. Its long, human-written Russian phrase is not generated by external libraries and serves as a reliable mechanism to prevent multiple instances of the malware from running simultaneously. From a detection standpoint, this mutex acts as a strong fingerprint for the Nefilim family. Another important aspect is the cryptographic initialization routine. The malware explicitly relies on the Windows CryptoAPI, acquiring a cryptographic provider and deriving an internal encryption key through a well-defined sequence: hashing attacker-controlled data using SHA-1 and subsequently deriving an AES key from that hash. This sequence is not only consistent across samples but also tightly coupled with unique input data, including embedded Russian phrases that act as cryptographic seeds.

Additionally, the presence of a well-defined ransom note name and the internal use of the “NEFILIM” identifier further reinforce the attribution. When correlated with the mutex, cryptographic routines, and ransom-related artifacts, these indicators provide a reliable foundation for detection with a low risk of false positives.

```yara
import "pe"

rule win_nefilim_ransomware_
{
    meta:
        author = "Ozyy"
        date = "2025-11-15"
        description = "Detects Nefilim ransomware based on mutex, crypto usage and ransom artifacts"
        family = "Nefilim"
        malware_type = "ransomware"

    strings:
        $mutex = "Den'gi plyvut v karmany rekoy. My khodim po krayu nozha..." ascii

        
        $crypto_blob_1 = "P28bYetqAjMJwFdCu5KwgN5PGwkVckpRko+" ascii
        $crypto_blob_2 = "uTCpaWeKoTIK27f4cF8GbrTFtiCBEPGFK" ascii


        $nefilim_w = "NEFILIM" wide
        $nefilim_a = "NEFILIM" ascii

        $ransom_note = "NEFILIM-DECRYPT.txt" ascii wide

        $rus_seed1 = "ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'" ascii

        $api1 = "CryptAcquireContextA" ascii
        $api2 = "CryptCreateHash" ascii
        $api3 = "CryptHashData" ascii
        $api4 = "CryptDeriveKey" ascii

        $sha1_alg = { 04 80 00 00 }   /* CALG_SHA1 = 0x8004 */
        $aes_alg  = { 01 68 00 00 }   /* CALG_AES_256 = 0x6801 */

    condition:
        pe.is_pe
        and pe.machine == pe.MACHINE_I386
        and pe.imports("KERNEL32.dll", "CreateMutexA")
        and pe.imports("ADVAPI32.dll", "CryptAcquireContextA")
        and (
            $mutex
            or
            (
                $ransom_note
                and 1 of ($rus_seed*)
                and 1 of ($crypto_blob_*)

            )
        )
        and all of ($api*)
        and ( $sha1_alg or $aes_alg )
        
}
```

## Conclusion
That’s all. Thank you for reading this far. I plan to publish more posts analyzing and developing malware at this level. If you have any questions or feedback, feel free to contact me.
