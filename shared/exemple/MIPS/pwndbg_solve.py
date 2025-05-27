from pwn import *
from archipwn import MultiArchDebugger
import os

class Prog:
    def __init__(self):
        self.io = None
        self.multiarch = None
        self.BINARY= "./ch64/ch64"
        self.GDB_PORT = 1234
        self.GDB_VERSION = "pwndbg"
        self.DISABLE_ASLR = True
        self.TMUX = True
        self.LIBC_DIR= "ch64" # ici il faut mettre là ou se trouve le répertoire "lib"
        self.BREAKPOINTS=[]

    def load_binaries(self):
        self.ELF = ELF(self.BINARY)
        self.LIBC = os.path.join(self.LIBC_DIR,"libc.so.6")
        self.ELF_FUNCTIONS = [func for func in self.ELF.functions]
        print(f"ELF_FUNCTIONS : {self.ELF_FUNCTIONS}")

PROG = Prog()
PROG.multiarch = MultiArchDebugger(
    PROG.BINARY, PROG.GDB_VERSION ,PROG.GDB_PORT, PROG.DISABLE_ASLR,
    PROG.TMUX, PROG.BREAKPOINTS, PROG.LIBC_DIR)
PROG.load_binaries()
PROG.io = PROG.multiarch.launch()
PROG.io.interactive()



