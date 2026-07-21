# Privilege Separation and User Space Sandbox

This project contains Linux C programs for two coursework tasks:

- `Frontend.c` and `Backend.c`: privilege-separated authentication using two independent processes, UNIX domain socket IPC, POSIX shared memory, request validation, and irreversible privilege dropping with `setresuid`.
- `Sandbox.c`: a parent controller that runs an untrusted child with `fork` and `execve`, monitors it externally with pthreads, and terminates it with signals when policy limits are exceeded.

## Build

Run on Linux:

```sh
make
```

## Privilege Separation Demo

Accepted demo credential:

```sh
./Frontend alice
```

Rejected examples:

```sh
./Frontend alice wrong-password
./Frontend 'bad/user' wonderland
```

For quick scripted tests, the password can still be provided as the second argument:

```sh
./Frontend alice wonderland
```

The frontend creates a UNIX domain `socketpair`, forks, and uses `execve("./Backend", ...)`. It sends a POSIX shared-memory file descriptor to the backend with `sendmsg` and `SCM_RIGHTS`. The backend verifies the peer with `SO_PEERCRED`, validates the request, drops GID and UID privileges with `setresgid` and `setresuid`, checks `geteuid`, prints selected `/proc/self/status` identity lines, authenticates, then clears the shared password buffer.

## Sandbox Demo

```sh
./Sandbox ./test_binaries/quick_exit
SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/sleeper
SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/cpu_hog
SANDBOX_RSS_LIMIT_KB=12000 ./Sandbox ./test_binaries/memory_hog
cat sandbox.log
```

The sandbox puts the child into its own process group and sends termination signals to that group, so child-created helper processes are cleaned up too. The sample log format is in `logs/sample_sandbox.log`.

## Important Files

- `Frontend.c`: unprivileged UI-facing process and process launcher.
- `Backend.c`: isolated authentication backend with validation and `setresuid`.
- `Sandbox.c`: process-control sandbox controller.
- `test_binaries/*.c`: harmless test programs that exit, sleep, spin, or allocate memory.
- `REPORT.md`: analysis, investigation answers, and verification method.
