import shutil
import sys
import os
import time
import subprocess
from pwn import ELF, context, log, process

class MultiArchDebugger:
    """
    Automated multi-architecture debugger using QEMU and GDB Multiarch.

    Args:
        binary_path (str): Path to the target binary.
        gdb_port (int): TCP port for GDB remote. Default 1235.
        disable_aslr (bool): Whether to disable ASLR via setarch -R. Default True.
        tmux_split (bool): Whether to launch inside a tmux split. Default True.
        breakpoints (list[int or str]): List of breakpoints (addresses or symbols). Default [].
        lib_override (str): Optional custom library path (directory or .so file) to use for the target.
    """
    DEFAULT_QEMU = {
        "arm":     "qemu-arm",
        "aarch64": "qemu-aarch64",
        "mips":    "qemu-mips",
        "riscv64": "qemu-riscv64",
        "i386":    "qemu-i386",
        "amd64":   "qemu-x86_64",
    }

    REQUIRED_CMDS = [
        ("gdb-multiarch", "GDB Multiarch", "sudo apt-get install gdb-multiarch"),
        ("tmux",         "tmux terminal",    "sudo apt-get install tmux"),
    ]
    REQUIRED_LIBS = [
        ("arm",     "arm-linux-gnueabihf",  "sudo apt-get install libc6-dev-armhf-cross"),
        ("aarch64", "aarch64-linux-gnu",   "sudo apt-get install libc6-dev-arm64-cross"),
        ("mips",    "mips-linux-gnu",      "sudo apt-get install libc6-dev-mips-cross"),
        ("riscv64", "riscv64-linux-gnu",   "sudo apt-get install libc6-dev-riscv64-cross"),
        ("i386",    "i386-linux-gnu",      "sudo apt-get install libc6-dev-i386-cross"),
        ("amd64",   "x86_64-linux-gnu",    "sudo apt-get install libc6-dev-amd64-cross"),
    ]

    def __init__(self, binary_path, gdbversion=None , gdb_port=1235,
                 disable_aslr=True, tmux_split=True,
                 breakpoints=None, lib_override=None):
        self.binary = binary_path
        if gdbversion:
            self.gdb_version = "gdb-multiarch -q -ex init-" + gdbversion # init-peda / init-gef / init-pwndbg
        else : 
            self.gdb_version = "gdb-multiarch"
        self.gdb_port = gdb_port
        self.disable_aslr = disable_aslr
        self.tmux_split = tmux_split
        self.tmux_cmd = ["tmux", "splitw", "-h"]
        self.breakpoints = breakpoints or []
        self.lib_override = lib_override
        self.libs_path = {}
        self.qemu_cmd = None

    def check_dependencies(self):
        missing = []
        libs = {}
        for exe, desc, hint in self.REQUIRED_CMDS:
            if shutil.which(exe) is None:
                missing.append((desc, hint))
        for arch, folder, hint in self.REQUIRED_LIBS:
            if self.lib_override and os.path.isfile(self.lib_override) and arch == context.arch:
                continue
            if self.lib_override and os.path.isdir(self.lib_override):
                libs[arch] = self.lib_override
                continue
            for base in ("/usr", "/usr/lib"):
                path = os.path.join(base, folder)
                if os.path.isdir(path):
                    libs[arch] = path
                    break
            else:
                missing.append((arch, hint))
        if missing:
            msgs = "\n".join(f"{name}: {tip}" for name, tip in missing)
            sys.exit(f"Dépendances manquantes:\n{msgs}")
        self.libs_path = libs
        log.info("Dépendances OK: %s", libs)
        return libs

    def setup_context(self):
        elf = ELF(self.binary)
        context.arch = elf.arch
        context.binary = self.binary
        log.info(f"=== Contexte -> arch: {context.arch}, binary: {self.binary}")

    def build_qemu_command(self):
        arch = context.arch
        if arch not in self.DEFAULT_QEMU:
            raise ValueError(f"Architecture inconnue: {arch}")
        base = self.DEFAULT_QEMU[arch]
        if self.lib_override :
            if os.path.isdir(self.lib_override):
                lib_path = self.lib_override
            else:
                print("#### ERROR in build_qemu_command : given arg for lib is not a dir")
                exit(1)
        else:
            lib_path = self.libs_path.get(arch)
        cmd = [base, "-g", str(self.gdb_port), "-L", lib_path, self.binary]
        if self.disable_aslr:
            cmd = ["setarch", os.uname().machine, "-R"] + cmd
        return cmd

    def launch(self):
        self.check_dependencies()
        self.setup_context()
        self.qemu_cmd = self.build_qemu_command()
        log.info("QEMU command: %s", self.qemu_cmd)

        if self.tmux_split and "TMUX" not in os.environ:
            sys.exit("Erreur: lancez ce script dans tmux.")

        # prepare env
        env = os.environ.copy()
        if self.lib_override and os.path.isfile(self.lib_override):
            env["LD_PRELOAD"] = os.path.abspath(self.lib_override)
            log.info("LD_PRELOAD=%s", env["LD_PRELOAD"])

        # launch QEMU with pwntools process
        process_cmd = self.qemu_cmd
        p = process(process_cmd, env=env)  # pwntools process
        time.sleep(0.5)
        log.info("QEMU démarré via pwntools, prête pour GDB.")

        # attach GDB with tmux send-keys
        self._attach_gdb()
        return p

    def _attach_gdb(self):
        cmds = [f" -ex 'symbol-file {self.binary}'",
                f" -ex 'set solib-search-path {self.libs_path.get(context.arch)}'",
                f" -ex 'set architecture {context.arch}'",
                f" -ex 'target remote localhost:{self.gdb_port}'",
                " -ex 'unset env LINES'",
                " -ex 'unset env COLUMNS'"]
        for bp in self.breakpoints:
            cmds.append(f" -ex 'b*{bp}'")
        #cmds.append(" -ex continue")
        gdb_cmd = [self.gdb_version] + cmds

        subprocess.Popen(self.tmux_cmd + ["".join(gdb_cmd)])
        log.info("GDB attaché on port %d.", self.gdb_port)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="MultiArch Debugger")
    parser.add_argument('binary')
    parser.add_argument('--port', type=int, default=1235)
    parser.add_argument('--no-aslr', action='store_false', dest='disable_aslr')
    parser.add_argument('--no-tmux', action='store_false', dest='tmux_split')
    parser.add_argument('-b', '--break', dest='breakpoints', nargs='*', default=[] )
    parser.add_argument('--lib', dest='lib_override')
    args = parser.parse_args()
    dbg = MultiArchDebugger(
        args.binary, args.port, args.disable_aslr,
        args.tmux_split, args.breakpoints, args.lib_override)
    io = dbg.launch()
    io.interactive()
