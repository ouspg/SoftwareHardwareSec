# Lab 3 remote targets & automatic grading

This directory contains the infrastructure required to build and deploy reproducible, containerized target environments for Task 1, 2 and 3. The upcoming experimental platform shares the logic in here for automatic grading.
**Task 4 is excluded from the automatic grading and everyone must make a writeup if they want to complete it!**

To ensure fair grading and consistent debugging across diverse host environments, we use a pinned Nix flake (`flake.nix`) packaged inside a lightweight Docker container. This setup produces byte-identical binaries and dynamic library closures for all students, with variations introduced only through personalized parameters (buffer sizes and flag strings).

You should do the local process first, and then as a final step, you automate the flag extraction with `pwntools`.

> [!NOTE]
> Before you begin, note a few practical differences between the introductory local examples in the lab and these containerized targets.

While the standalone local programs generally accept payloads via command-line arguments (`argv`), the remote targets operate as network services over TCP that read from standard input (`stdin`) and print task-specific memory leaks upon connection. Additionally, these challenges are strictly compiled as 32-bit x86 binaries with individualized buffer sizes, running under an unprivileged `player` user where the objective is to capture the protected flag in `/home/player`.

## Building a target image

You can build a container image for any specific task by passing build arguments to Docker:

```bash
docker build \
  --build-arg TASK=1 \
  --build-arg BUFSIZE=64 \
  --build-arg FLAG='flag{example_flag_here}' \
  -t lab3shellcoding-task1 .
```

Task 3 comes in two parts. Part `B` is the setuid variant:

```bash
docker build \
  --build-arg TASK=3 \
  --build-arg PART=B \
  --build-arg BUFSIZE=64 \
  --build-arg FLAG='flag{example_flag_here}' \
  -t lab3shellcoding-task3b .
```

If not running on AMD64 Linux directly, platforms must be listed explicitly: add `--build-arg "EXTRA_PLATFORMS=x86_64-linux i686-linux"`.

### Build Arguments

| Argument   |   Default   | Description                                                                                                                                                                                                                                                                                                                                                             |
| :--------- | :---------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TASK`     |     `1`     | Selects the task challenge: <br>• `1`: `ret2win` (control-flow hijack to `secret()`)<br>• `2`: Stack-based shellcoding (`-z execstack`)<br>• `3`: Return-to-libc (`-z noexecstack`)                                                                                                                                                                                     |
| `BUFSIZE`  |    `64`     | Allocated buffer size in bytes (`48`–`120`). Configured per challenge instance.                                                                                                                                                                                                                                                                                         |
| `FLAG`     | `flag{...}` | Contents of the flag file (up to 128 characters). Also determines the flag's filename.                                                                                                                                                                                                                                                                                  |
| `FLAGNAME` |   derived   | Basename of the flag file, defaults to `<16 hex of sha256(FLAG)>_flag.txt`.                                                                                                                                                                                                                                                                                             |
| `PART`     |     `A`     | Only used by `TASK=3`.<br>• `A`: the flag is readable by `player`, so `system("/bin/sh")` followed by `ls` and `cat` is enough.<br>• `B`: the flag is `0400 root` and the binary is setuid root, so only the process itself can read it. The binary also prints the flag path, which makes the task easier, as the part `B` has no usable shell with `root` privileges. |

---

## Running the Container

Once built, start the challenge container in detached mode and expose port `1337`:

```bash
docker run -d --rm -p 1337:1337 lab3shellcoding-task1
```

You can interact with the challenge over TCP using `nc` (netcat) or automate your exploit with `pwntools`:

```bash
nc localhost 1337
```

```python
from pwn import *

io = remote('localhost', 1337)
print(io.recvline().decode())
```

The target process expects input over standard input without requiring an interactive TTY.

---

## Container environment

The container is built from a minimal `scratch` image containing only the essential Nix closure (~111 MB):

- `/bin/overflow` (symlinked into `/nix/store`), compiled in 32-bit mode with task-specific compiler flags.
- Pinned 32-bit GNU C Library (`glibc`), dynamic linker (`ld-linux.so.2`), `socat`, standard coreutils, and a basic shell.

Upon connection, the service emits an information leak corresponding to the selected task, as we can't use `gdb` anymore to obtain some basic information:

| Task | Leak                         | Meaning                                          |
| :--: | :--------------------------- | :----------------------------------------------- |
|  1   | `[*] base @ <addr>`          | Executable base address                          |
|  2   | `[*] stack @ <addr>`         | Stack buffer address                             |
|  3   | `[*] system @ <addr>`        | Resolved address of `system()` in `glibc`        |
|  3B  | `[*] flag @ <addr> (<path>)` | Address and full path of the root-only flag file |

> [!NOTE]
> The helper function `secret()` is only compiled into Task 1. Tasks 2 and 3 require executing shellcode or chaining standard library calls.

The flag file is named after the per-instance flag instead of `flag.txt`, and the same token names the store paths that hold it, so neither the file nor its location has a fixed name. Intention is to make printing the flag slightly more difficult e.g. you need to chain `ls` and then `cat` based on the correct path.

## Extracting target binaries and libraries

To develop and test your exploit locally, you must inspect the exact binary and `libc` shared object shipped in the container. Discrepancies in `glibc` versions or compiler optimizations will alter function offsets and ROP gadgets.

### Option A: Extracting from the Docker image

You can copy the artifacts directly out of a built container:

```bash
# 1. Create a dummy container instance
docker create --name lab3 lab3shellcoding-task2
# 2. Extract the target binary
docker cp -L lab3:/bin/overflow ./overflow
# 3. Locate the interpreter path to find the exact glibc store directory
readelf -l ./overflow | grep interpreter
# Example output: /nix/store/<glibc-hash>-glibc-2.42-84/lib/ld-linux.so.2
# The image carries both a 32-bit and a 64-bit glibc; the interpreter in the
# binary tells you which one to take.
# 4. Extract the matching libc.so.6
docker cp -L lab3:/nix/store/<glibc-hash>-glibc-2.42-84/lib/libc.so.6 ./libc.so.6
# 5. Clean up the container
docker rm lab3
# 6. Verify checksums
sha256sum overflow libc.so.6
```

### Option B: Building and inspecting via Nix directly (can be complex!)

If you have Nix installed on an `x86_64-linux` host, you can instantiate the exact package directly without Docker:

```bash
nix build --impure --print-out-paths .#packages.x86_64-linux.task2-b64
readelf -l result/bin/overflow
```

The runtime libraries `libc.so.6` and `ld-linux.so.2` reside in the companion `/nix/store` glibc directory identified by `readelf`.
