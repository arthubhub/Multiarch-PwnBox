# auto\_arch\_pwntools

**AutoArchPwntools** est un outil de débogage multi-architecture basé sur Pwntools et QEMU. Il permet de lancer automatiquement un binaire dans QEMU, d’y attacher GDB Multiarch et de gérer les environnements de bibliothèques (libc, ld) pour diverses architectures (x86\_64, ARM32/64, MIPS, RISC-V, etc.).

Ce projet est en développement, si vous trouvez une incompatibilité ou un dysfonctionnement, créez une issue !

---

## 🚀 Fonctionnalités

* **Détection automatique des dépendances** (QEMU, toolchains, libs) et suggestions d’installation.
* **Support multi-architecture** : x86 (i386/amd64), ARM32/ARM64, MIPS, RISC‑V.
* **Integration Pwntools** : création du process QEMU via `pwn.process()` pour interagir (recv, send, interactive).
* **Attachement GDB Multiarch** dans un split tmux (ou via envoi de commandes) avec gestion des breakpoints.
* **Override de bibliothèque** : possibilité de charger une libc personnalisée ou un sysroot complet (`--lib /chemin/vers/libc.so.6` ou vers dossier).
* **Dockerfile préconfiguré** pour obtenir un conteneur prêt à l’emploi.
* **Script de compilation multi-arch** (`multi_compile.sh`) pour générer des vulnérables sur toutes les architectures.

---

## 📦 Prérequis

* **Docker** (pour utiliser l’image Docker fournie)
* **tmux** (optionnel si `--no-tmux`) (local)
* **Python 3.10+** et **pip** (local)
* **Pwntools**, **pycryptodome** (installés via pip) (local)

---

## ⚙️ Installation

### Télécharger le repo

```bash
git clone [https://github.com/arthubhub/auto_arch_pwntools.git](https://github.com/arthubhub/auto_arch_pwntools.git)
```

### Avec Docker

```bash
docker build -t auto_arch_pwntools .
# Monter le répertoire shared pour accéder aux scripts et binaires
docker run -it --rm -v "$(pwd)/shared:/shared" auto_arch_pwntools
```

Sinon, vous pouvez le lancer avec `run.sh`

---

## 🚩 Structure du projet

```text
auto_arch_pwntools/
├── BOF ON ANY ARCH.md        # Notes sur les buffer overflows multi-arch
├── Dockerfile                # Image Docker préconfigurée
├── README.md                 # Ce fichier
├── run.sh                    # Wrapper pour lancer le débogueur
└── shared
    ├── archipwn.py           # Script principal / classe MultiArchDebugger
    ├── exemple
    │   ├── archipwn.py       # Copie du script principal
    │   ├── ch64              # Dossier mini-rootfs MIPS 64
    │   │   ├── ch64          # Binaire MIPS
    │   │   ├── lib
    │   │   │   ├── ld.so.1
    │   │   │   └── libc.so.6
    │   │   └── run.sh
    │   └── solve.py          # Exemple d’utilisation programmée
    └── test                  # Binaries de test multi-arch
        ├── amd64
        ├── arm32
        ├── arm64
        ├── i386
        ├── mips
        ├── riscv64
        ├── vuln.c
        └── multi_compile.sh  # Script de compilation multi-target
```

---

## 📖 Usage

### Ligne de commande

```bash
# Mode interactif (dans tmux)
python3 archipwn.py --binary ./test/amd64/solaris/chall --break main --lib ./test/amd64/solaris
```

### Exécution depuis un script Python

```python
from archipwn import MultiArchDebugger

dbg = MultiArchDebugger(
    binary_path='./ch64/ch64',
    gdb_port=1234,
    disable_aslr=True,
    tmux_split=True,
    breakpoints=['main'],
    lib_override='ch64'
)
dbg.launch().interactive()
```

### Exemple :

- Lancez docker et mettez en place l'environnement (fichiers et librairies si besoin). Créez un fichier de base pour tester votre exécutable.
<img width="779" alt="image" src="https://github.com/user-attachments/assets/a3bc40b1-b286-40e9-b725-abdef6704003" />

- Lancez tmux pour avoir deux écrans, changez d'écrans avec ctrl + b puis <- ou ->, scrollez avec ctrl + b puis '['. Ensuite, exécuter votre programme, n'oubliez pas de réaliser une action ( eg p.interactive() ), sinon le processus s'arrêtera.
<img width="1447" alt="image" src="https://github.com/user-attachments/assets/ac685753-637a-437e-bc0f-e923299bd9bb" />

- Le programme a détecté du 'MIPS 32', vous pouvez analyser le code dynamiquement avec gdb !
Ensuite, créez votre exploit selon vos goûts et placez vos breakpoints là où vous avez besoin pour votre analyse.



---

## 🤝 Contribuer

1. Forkez ce dépôt
2. Créez une branche : `git checkout -b feature/ma-nouvelle-fonction`
3. Committez vos changements : `git commit -m 'Ajoute une nouvelle feature'`
4. Poussez : `git push origin feature/ma-nouvelle-fonction`
5. Ouvrez une Pull Request

---

## 📄 License

Ce projet est distribué sous licence MIT. Consultez le fichier `LICENSE` pour plus de détails.
