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
            if gdbversion == "gef":
                self.gdb_version = "LC_ALL=C.UTF-8 gdb-multiarch -ex init-gef" # init-gef 
            else:
                self.gdb_version = "gdb-multiarch -ex init-" + gdbversion # init-peda / init-pwndbg
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
        self.debug_mode = True

    def check_dependencies(self):
        missing = []
        libs = {}

        # d'abord, check des commandes
        for exe, desc, hint in self.REQUIRED_CMDS:
            if shutil.which(exe) is None:
                missing.append((desc, hint))

        # si on a un override, on vérifie que le chemin existe, puis on l'assigne à toutes les arch
        if self.lib_override:
            if not os.path.exists(self.lib_override):
                missing.append(("lib_override", f"Le chemin spécifié n'existe pas : {self.lib_override}"))
            else:
                for arch in self.DEFAULT_QEMU:
                    libs[arch] = self.lib_override
                if missing:
                    msg = "\n".join(f"{n}: {t}" for n, t in missing)
                    sys.exit(f"Dépendances manquantes:\n{msg}")
                self.libs_path = libs
                log.info("Dépendances OK (override libs): %s", libs)
                return libs

        # sinon, pas d'override, on cherche les libs classiques
        for arch, folder, hint in self.REQUIRED_LIBS:
            for base in ("/usr", "/usr/lib"):
                path = os.path.join(base, folder)
                if os.path.isdir(path):
                    libs[arch] = path
                    break
            else:
                missing.append((arch, hint))

        if missing:
            msg = "\n".join(f"{n}: {t}" for n, t in missing)
            sys.exit(f"Dépendances manquantes:\n{msg}")

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

        qemu_bin = self.DEFAULT_QEMU[arch]
        lib_path = self.libs_path[arch]   # plus d'override ici, c'est centralisé dans check_dependencies

        cmd = [qemu_bin]
        if self.debug_mode:
            cmd += ["-g", str(self.gdb_port)]
        cmd += ["-L", lib_path, self.binary]

        if self.disable_aslr:
            cmd = ["setarch", os.uname().machine, "-R"] + cmd

        return cmd

    def _qemu_config(self):
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
        self.qemu_proc = process(self.qemu_cmd, env=env)  # pwntools process
        if self.debug_mode : time.sleep(0.5)
        log.info("QEMU demarre via pwntools")
        return self.qemu_proc

    def _attach_gdb(self):
        """ Commands to be ran :
        - set debuginfod enabled on
        - file <file_path>
        - set sysroot <path wher to find /lib>
        - set architecture <arch>
        - target remote localhost:<port>
        - unset env ..."""



        cmds = [f" -ex 'set debuginfod enabled on'",
                f" -ex 'file {self.binary}'",
                f" -ex 'set sysroot {self.libs_path.get(context.arch)}'"
                f" -ex 'set solib-search-path {self.libs_path.get(context.arch)}'",
                f" -ex 'set architecture {context.arch}'",
                f" -ex 'target remote localhost:{self.gdb_port}'",
                " -ex 'unset env LINES'",
                " -ex 'unset env COLUMNS'"]
        for bp in self.breakpoints:
            cmds.append(f" -ex 'b*{bp}'")
        #cmds.append(" -ex continue")
        gdb_cmd = [self.gdb_version] + cmds
        
        self.gdb_proc = subprocess.Popen(self.tmux_cmd + ["".join(gdb_cmd)])
        print("".join(gdb_cmd))
        log.info("GDB attaché")
        return self.gdb_proc
    
    def shutdown(self, timeout: float = 0.5):
        """
        Arrête QEMU et GDB , en coupant proprement les processes.
        """
        # QEMU
        if hasattr(self, "qemu_proc") and self.qemu_proc:
            try:
                self.qemu_proc.close()       # pour pwntools.Process
                self.qemu_proc.wait(timeout) # on attend un peu
            except Exception:
                self.qemu_proc.kill()
            finally:
                self.qemu_proc = None

        # GDB
        if hasattr(self, "gdb_proc") and self.gdb_proc:
            try:
                self.gdb_proc.terminate()
                self.gdb_proc.wait(timeout)
            except Exception:
                self.gdb_proc.kill()
            finally:
                self.gdb_proc = None
        log.info("Tous les processus QEMU/GDB ont ete arretes.")
    
    def launch(self):
        # exécution seule
        self.debug_mode = False
        return self._qemu_config()

    def debug(self):
        # exécution + attachement GDB
        self.debug_mode = True
        p = self._qemu_config()
        self._attach_gdb()
        return p




if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="MultiArch Debugger")
    parser.add_argument('binary')
    parser.add_argument('--gdb_version', )
    parser.add_argument('--port', type=int, default=1235)
    parser.add_argument('--no-aslr', action='store_false', dest='disable_aslr')
    parser.add_argument('--no-tmux', action='store_false', dest='tmux_split')
    parser.add_argument('-b', '--break', dest='breakpoints', nargs='*', default=[] )
    parser.add_argument('--lib', dest='lib_override')
    args = parser.parse_args()
    dbg = MultiArchDebugger(
        args.binary, args.gdb_version , args.port, args.disable_aslr,
        args.tmux_split, args.breakpoints, args.lib_override)
    io = dbg.launch()
    io.interactive()
