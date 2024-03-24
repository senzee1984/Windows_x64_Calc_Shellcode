## Windows/x64 - PIC Null-Free Calc.exe Shellcode (173 Bytes)

### Shellcode Author:    Senzee
##### OS Architecture:   Windows x64
##### Tested On:         Windows 11 Home 10.0.22621, Windows Server 2022 Standard 10.0.20348, Windows Server 2019 Datacenter 10.0.17763
##### Shellcode Size:    173 bytes
##### Null-Free:         True

![image](/screenshot/calc.jpg)


## Shellcode Description
Null-Free, PIC, and extremely small-size Windows x64 shellcode that pops `calc.exe` program, can be used to test shellcode injection and/or code execution. The shellcode works by dynamically resolving the base address of `kernel32.dll` via `PEB` and `ExportTable` method. 

To resolve the base address of `kernel32.dll`, the steps are as follows:

1. Locate the address of `TEB` in the Intel `GS` register
2. Locate the address of `PEB` in the TEB structure
3. Locate `_PEB_LDR_DATA` structure in PEB structure
4. Get the head of doubly-linked list `InMemoryOrderModuleList`
5. The 3rd entry of doubly-linked list InMemoryOrderModuleList: `program.exe(shellcode loading program) -> ntdll.dll -> kernel32.dll`
6. Find DllBase of the current module in `_LDR_DATA_TABLE_ENTRY structure`

After getting the base address of kernel32.dll, parse kernel32.dll and locate `WinExec` function. The steps are as follows:

1. Locate the `Export Directory`
2. Get the `number of function names` and use it as an index
3. Locate the `Export Name Pointer Table`.
4. Use function name hashing approach to avoid the use of function name
5. Compare the WinExec's hash with the current function's hash in the loop
6. Get the address of WinExec, supply proper arguments, and call it.

Argument lpCmdLine is `"calc.exe"`, argument `uCmdShow` is `1`.

```c++
UINT WinExec(
  [in] LPCSTR lpCmdLine,
  [in] UINT   uCmdShow
);
```



