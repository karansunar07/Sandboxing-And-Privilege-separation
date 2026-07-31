diff --git a/README.md b/README.md
index 2b72631..66a1066 100644
--- a/README.md
+++ b/README.md
@@ -1,26 +1,132 @@
-# Privilege Separation and User Space Sandbox
+# Sandboxing and Privilege Separation
 
-This project contains Linux C programs for two coursework tasks:
+This repository contains a Linux C implementation for two operating-systems security tasks:
 
-- `Frontend.c` and `Backend.c`: privilege-separated authentication using two independent processes, UNIX domain socket IPC, POSIX shared memory, request validation, and irreversible privilege dropping with `setresuid`.
-- `Sandbox.c`: a parent controller that runs an untrusted child with `fork` and `execve`, monitors it externally with pthreads, and terminates it with signals when policy limits are exceeded.
+1. **Privilege-separated password validation**
+2. **User-space malware analysis sandboxing**
+
+The project demonstrates how Unix/Linux process isolation, secure inter-process communication, privilege management, shared memory, external process monitoring, pthread-based concurrency, and signal-based enforcement can be combined to reduce risk when handling sensitive authentication data or running untrusted executables.
+
+## Project Overview
+
+### Task 1: Privilege-Separated Authentication
+
+`Frontend.c` and `Backend.c` implement a small authentication service split across two independent executables.
+
+The frontend is responsible for user interaction and process launch. The backend is responsible for request validation, runtime identity checks, privilege dropping, and the authentication decision. The design avoids placing all trusted and untrusted behavior inside one process.
+
+Key mechanisms:
+
+- Separate processes using `fork()` and `execve()`
+- UNIX domain socket IPC using `socketpair()`
+- File descriptor passing with `sendmsg()`, `recvmsg()`, and `SCM_RIGHTS`
+- Peer credential verification with `SO_PEERCRED`
+- POSIX shared memory password buffer using `shm_open()` and `mmap()`
+- Privilege dropping with `setresgid()` and `setresuid()`
+- Runtime verification using `geteuid()`, `getegid()`, and `/proc/self/status`
+- Explicit clearing of sensitive password memory
+- Backend-side request validation and rejection
+
+### Task 2: User-Space Sandbox
+
+`Sandbox.c` implements a user-space sandbox controller for running untrusted test binaries under external supervision.
+
+The sandbox starts a child process with `fork()`, replaces the child image with an unsafe binary using `execve()`, and monitors the child from the parent process. The untrusted program does not participate in its own monitoring or termination.
+
+Key mechanisms:
+
+- Parent-child process isolation
+- `execve()` execution of untrusted binaries
+- External monitoring through `/proc`
+- Resource limits with `setrlimit()`
+- Concurrent monitoring using `pthread_create()`
+- Race-controlled shared monitor state using `pthread_mutex_t`
+- Time and memory policy enforcement
+- Termination using `SIGTERM` and `SIGKILL`
+- Process-group cleanup using `setpgid()` and group signaling
+
+## Repository Structure
+
+```text
+.
+├── Backend.c
+├── Frontend.c
+├── Sandbox.c
+├── Makefile
+├── README.md
+├── REPORT.md
+├── logs/
+│   └── sample_sandbox.log
+└── test_binaries/
+    ├── cpu_hog.c
+    ├── memory_hog.c
+    ├── quick_exit.c
+    └── sleeper.c
+```
+
+## Requirements
+
+This project is intended for Linux.
+
+Required tools:
+
+- `gcc`
+- `make`
+- POSIX/Linux system headers
+- Optional: `strace` and `objdump` for verification evidence
+
+Install common build tools on Debian/Ubuntu:
+
+```sh
+sudo apt update
+sudo apt install build-essential strace binutils
+```
 
 ## Build
 
-Run on Linux:
+Build all programs:
 
 ```sh
 make
 ```
 
-## Privilege Separation Demo
+This creates:
+
+- `Frontend`
+- `Backend`
+- `Sandbox`
+- `test_binaries/quick_exit`
+- `test_binaries/sleeper`
+- `test_binaries/cpu_hog`
+- `test_binaries/memory_hog`
+
+Clean generated binaries and logs:
+
+```sh
+make clean
+```
+
+## Running Task 1
 
 Accepted demo credential:
 
+```text
+username: alice
+password: wonderland
+```
+
+Interactive password input:
+
 ```sh
 ./Frontend alice
 ```
 
+Scripted test:
+
+```sh
+./Frontend alice wonderland
+```
+
 Rejected examples:
 
 ```sh
@@ -28,30 +134,88 @@ Rejected examples:
 ./Frontend 'bad/user' wonderland
 ```
 
-For quick scripted tests, the password can still be provided as the second argument:
+Expected successful output includes backend identity information, peer credentials, privilege-drop confirmation, and `/proc/self/status` UID/GID lines.
+
+## Running Task 2
+
+Run a harmless binary:
 
 ```sh
-./Frontend alice wonderland
+./Sandbox ./test_binaries/quick_exit
 ```
 
-The frontend creates a UNIX domain `socketpair`, forks, and uses `execve("./Backend", ...)`. It sends a POSIX shared-memory file descriptor to the backend with `sendmsg` and `SCM_RIGHTS`. The backend verifies the peer with `SO_PEERCRED`, validates the request, drops GID and UID privileges with `setresgid` and `setresuid`, checks `geteuid`, prints selected `/proc/self/status` identity lines, authenticates, then clears the shared password buffer.
-
-## Sandbox Demo
+Trigger time-limit enforcement:
 
 ```sh
-./Sandbox ./test_binaries/quick_exit
 SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/sleeper
+```
+
+Trigger enforcement against a CPU-bound process:
+
+```sh
 SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/cpu_hog
+```
+
+Trigger memory-limit enforcement:
+
+```sh
 SANDBOX_RSS_LIMIT_KB=12000 ./Sandbox ./test_binaries/memory_hog
+```
+
+View the sandbox log:
+
+```sh
 cat sandbox.log
 ```
 
-The sandbox puts the child into its own process group and sends termination signals to that group, so child-created helper processes are cleaned up too. The sample log format is in `logs/sample_sandbox.log`.
+A sample log is provided in:
+
+```text
+logs/sample_sandbox.log
+```
+
+## Verification Commands
+
+Confirm process creation, IPC, shared memory, and privilege-dropping syscalls:
+
+```sh
+strace -f -e trace=socketpair,sendmsg,recvmsg,execve,setresgid,setresuid,geteuid,mmap,munmap ./Frontend alice wonderland
+```
+
+Confirm the backend contains the privilege-dropping path:
+
+```sh
+objdump -d Backend | grep -A30 -E "setresuid|drop_privileges"
+```
+
+Run the full demonstration target:
+
+```sh
+make test
+```
+
+## Security Notes
+
+This project is educational and demonstrates operating-system mechanisms. It is not a complete production authentication system or a full malware containment platform.
+
+Important limitations:
+
+- Password validation uses a simple demonstration credential, not a password database or password hashing scheme.
+- The sandbox does not provide filesystem, network, namespace, cgroup, or seccomp isolation.
+- Real malware analysis should be performed inside disposable virtual machines or stronger containerized environments.
+- The sandbox is designed to demonstrate parent-controlled monitoring and termination, not complete hostile-code containment.
+
+## Report
+
+`REPORT.md` contains the written analysis for the assignment, including:
+
+- Task 1 investigation questions
+- Task 2 investigation questions
+- Verification and evidence plan
+- Design limitations
+- References
 
-## Important Files
+## Author
 
-- `Frontend.c`: unprivileged UI-facing process and process launcher.
-- `Backend.c`: isolated authentication backend with validation and `setresuid`.
-- `Sandbox.c`: process-control sandbox controller.
-- `test_binaries/*.c`: harmless test programs that exit, sleep, spin, or allocate memory.
-- `REPORT.md`: analysis, investigation answers, and verification method.
