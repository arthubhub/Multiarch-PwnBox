# Dockerfile pour compilation & debugging multi-arch (x86_64, ARM32/64, MIPS, RISC-V, Windows…)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root

# Installe QEMU, toolchains & dev headers, debuggers, Python3 + pwntools
RUN apt-get update && apt-get install -y --no-install-recommends \
      # émulation -> pour qemu
      binfmt-support \ 
      #qemu-user-static \
      #qemu-user \
      # toolchains & dev headers (cross) -> pour les tests
      build-essential \
      gcc \
      libc6-dev \
      # ARM32/ARMHF -> pour les tests et qemu
      gcc-arm-linux-gnueabi \
      libc6-dev-armhf-cross \
      # ARM64/AARCH64 -> pour les tests et qemu
      gcc-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      # MIPS -> pour les tests et qemu
      gcc-mips-linux-gnu \
      libc6-dev-mips-cross \
      # RISC-V64 -> pour les tests et qemu
      gcc-riscv64-linux-gnu \
      libc6-dev-riscv64-cross \
      # x86 i386  -> pour les tests et qemu
      lib32gcc-s1 \
      libc6-dev-i386-cross \
      # Windows PE (x86_64)  -> ca c'est pas utile pour le moment
      mingw-w64 \ 
      # Debuggers & outils -> important
      tmux \
      gdb \
      gdb-multiarch \
      git \
      # Python3 & pwntools -> important
      python3 \
      python3-pip \
      python3-venv \
      # six -> pour peda
      python3-six \
      # wget & certif & file -> pour GEF
      wget ca-certificates file \
      # for qemu :
      autoconf \
      libtool \
      pkg-config \
      libglib2.0-dev \
      libpixman-1-dev \
      libfdt-dev \
      zlib1g-dev \
      ninja-build \
      meson \
      && rm -rf /var/lib/apt/lists/*

# Update meson, ubuntu 24.04 Meson version is 1.3.2 but project requires >=1.5.0
RUN python3 -m pip install --upgrade meson --break-system-packages

# Compile qemu at a recent version (including gdbstubs for mappings)
RUN cd /usr/src \
      && git clone https://gitlab.com/qemu-project/qemu.git \
      && cd qemu \
      && git fetch --tags \
      && git checkout v10.0.2 \
      && mkdir build && cd build \
      && ../configure \
            --prefix=/usr/local \
            --target-list=arm-linux-user,aarch64-linux-user,mips-linux-user,riscv64-linux-user,i386-linux-user,x86_64-linux-user \
            --enable-debug \
      && ninja -C . install \
      && ldconfig

# Crée un venv à /opt/venv
RUN python3 -m venv /opt/venv
# Ajoute le venv au PATH pour que les commandes python passent par là
ENV PATH="/opt/venv/bin:${PATH}"

# Pour pwntools, modifiée pour le venv
RUN pip install --upgrade pip setuptools wheel \ 
 && pip install --no-cache-dir \
      --default-timeout=100 \
      --retries=5 \
      --resume-retries=5 \
      pycryptodome pwntools\
      six
    

# Crée les symlinks manquants pour i386-linux-gnu -> pour build & run en x86
RUN ln -s /usr/i686-linux-gnu       /usr/i386-linux-gnu \
 && mkdir -p /usr/lib/i386-linux-gnu \
 && ln -s /usr/lib32               /usr/lib/i386-linux-gnu

### PEDA GET PWNDBG ### -> BEGIN
# voir https://infosecwriteups.com/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8
# pwndbg -> voir la doc de pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg-src && \
      cd /opt/pwndbg-src && \
      ./setup.sh

# PEDA -> voir la doc de PEDA
RUN git clone https://github.com/longld/peda.git $HOME/peda \
      && rm -f $HOME/peda/lib/six.py \
      && rm -fr $HOME/peda/lib/six
# on enlève six ici car il est nul 

# GEF -> voir la doc de GEF
RUN wget -q -O $HOME/.gdbinit-gef.py \
      https://raw.githubusercontent.com/hugsy/gef/main/gef.py


# Script from host -> for custom commands in gdb
COPY dot_gdbinit $HOME/.gdbinit

# wrapper scripts in /usr/local/bin -> useless when called from python script but we can keep it
RUN for name in peda pwndbg gef; do \
    echo "#!/bin/sh" > /usr/local/bin/gdb-$name && \
    echo "exec gdb -q -ex init-$name \"\$@\"" >> /usr/local/bin/gdb-$name; \
done && chmod +x /usr/local/bin/gdb-*

### PEDA GET PWNDBG ### <- END

COPY init $HOME/init
RUN chmod +x $HOME/init


# Montez votre dossier ./shared ici
VOLUME ["/shared"]
WORKDIR /shared

ENV PYTHONPATH=/shared

CMD ["tmux", "new-session", "-A", "-s", "pwnbox", "$HOME/init"]
