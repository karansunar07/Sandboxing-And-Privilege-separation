
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
 
