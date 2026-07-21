# Security Analysis and Verification Report

## Task 1: Privilege-Separated Authentication

The first part of this project implements authentication as two independent Linux processes instead of one large process. `Frontend.c` is the user-facing process. It accepts a username and password, creates a UNIX domain socket pair, creates a POSIX shared-memory object for the password buffer, forks, and executes `Backend` with `execve`. `Backend.c` receives the request through the socket, receives the shared-memory file descriptor through `SCM_RIGHTS`, verifies the peer identity with `SO_PEERCRED`, validates the request fields, drops privilege with `setresuid`, checks the new effective UID with `geteuid`, prints selected `/proc/self/status` lines, and then performs the small demonstration authentication decision.

The demo credential is intentionally simple: username `alice` and password `wonderland`. It is not meant to be a production password database. Its purpose is to show operating-system separation, not password hashing policy. The frontend can read the password with terminal echo disabled, which avoids the normal command-line exposure problem during interactive use. For scripted tests, it still accepts a password argument and overwrites that argument memory as soon as it has copied it. The implementation avoids sending the password bytes directly as a normal socket payload. Instead, the password is placed in a POSIX shared-memory buffer created with mode `0600`, the name is unique to the frontend process, the name is unlinked immediately, and the open file descriptor is transferred to the backend over the already connected UNIX domain socket. The backend maps that descriptor after receiving it. After use, both sides clear the mapped memory with an explicit zeroing primitive.

### Verification Steps

Build the programs on Linux:

```sh
make
```

Run a successful request:

```sh
./Frontend alice
```

Enter `wonderland` at the password prompt. Expected observations include:

```text
Backend pid=... starting euid=...
Backend peer pid=... uid=... gid=...
Backend dropped privileges; geteuid=...
Uid:    ...
Gid:    ...
Backend result: ALLOW (validated after privilege drop)
```

Run rejected requests:

```sh
./Frontend alice wrong-password
./Frontend 'bad/user' wonderland
```

The first reaches the backend and is denied as an invalid credential. The second is rejected by frontend validation before IPC because the slash is not allowed. Backend validation repeats the same style of checks so that security does not depend only on the frontend behaving correctly.

A useful scripted run plus disassembly and syscall-oriented verification set is:

```sh
objdump -d Backend | grep -A20 -E 'setresuid|drop_privileges'
strace -f -e trace=socketpair,sendmsg,recvmsg,execve,setresgid,setresuid,geteuid,mmap,munmap ./Frontend alice wonderland
```

The `strace` output should show `execve("./Backend", ...)`, `sendmsg` and `recvmsg` for descriptor passing, and an actual `setresuid(...)` call from the backend process.

### Investigation Answers

1. It is insecure for a single process to both receive untrusted user input and access sensitive authentication data because one memory-safety bug, parser bug, format-string bug, injection flaw, or logic error can expose the entire privileged address space. A process is the unit that owns virtual memory, open descriptors, credentials, environment variables, and many security-relevant kernel attributes. If the same process parses attacker-controlled input and also holds authentication secrets or elevated privileges, an attacker who compromises the parser can often read memory, reuse open file descriptors, call privileged code paths, or modify control flow. Linux threads do not solve this because threads share the same address space and usually share the same process credentials. In contrast, separate processes create a kernel-enforced boundary: the frontend can be treated as exposed and untrusted, while the backend can be small, validated, and privilege-aware.

2. Least privilege can be enforced at the operating-system level by splitting duties across processes with different UIDs, GIDs, capabilities, file descriptors, namespaces, resource limits, and seccomp policies. A frontend process can run as the invoking user and handle command-line input. A backend process can start with only the privileges needed to open or inherit protected resources and then permanently drop to an unprivileged UID before processing the request. The kernel enforces the difference because each process has its own credentials and address space. Threads are weaker for this design because all threads in a process share memory and credentials; a compromised thread can read secrets from another thread or call privileged functions in the same process. Processes let the operating system deny access instead of relying only on programmer discipline.

3. If privilege dropping is implemented incorrectly, serious risks remain. A process may retain a saved set-user-ID of root and later regain root with `setuid(0)`. It may keep privileged supplementary groups. It may retain Linux capabilities even after changing UID. It may keep sensitive file descriptors open, such as descriptors to password databases, keys, sockets, or writable system files. It may drop privileges too late, after already parsing attacker-controlled input. It may fail to check return values from `setresuid`, leaving the process privileged when the developer assumes it is not. It may also run helper programs with a polluted environment. For that reason, this backend clears supplementary groups when running as root, calls `setresgid`, calls `setresuid`, compares `geteuid` and `getegid` with the target identity, prints `CapEff`, and attempts `setuid(0)` afterward. If regaining root succeeds, the runtime check fails.

4. Two independent processes can securely exchange authentication requests and results with UNIX domain sockets and descriptor passing. The socket gives a private communication channel created before `fork` or explicitly connected through a filesystem path with restrictive permissions. `SO_PEERCRED` lets the receiver inspect the peer process UID, GID, and PID. `SCM_RIGHTS` lets one process pass a file descriptor without exposing a public file path. In this project, the frontend sends the backend a request structure and a shared-memory file descriptor. The password bytes are in the shared-memory mapping rather than directly copied through ordinary command-line arguments, environment variables, or globally visible files. The backend validates the request before trusting lengths or names, then returns only an allow/deny result and a short message.

5. UNIX domain sockets are preferable to network sockets for local privileged communication because they never need to expose a TCP or UDP port to the network stack. They are local to the host, support filesystem permissions when pathname sockets are used, support peer credential checks, and support descriptor passing with `SCM_RIGHTS`. Network sockets are valuable for remote communication, but they create a larger attack surface: bind addresses, firewall rules, packet parsing, remote scanning, and accidental exposure. For local privilege separation, UNIX domain sockets express the intended trust boundary more directly.

6. Linux provides several mechanisms for controlled sharing between isolated processes. Pipes and socket pairs support byte-stream or packetized message passing. UNIX domain sockets support peer credentials and descriptor passing. POSIX shared memory and `mmap` support explicitly shared memory regions. `memfd_create` can create anonymous memory-backed files that can also be passed as descriptors. File locks, futexes, semaphores, and eventfd can coordinate access when shared state must be synchronized. These mechanisms preserve process isolation because sharing happens only through kernel-mediated objects, not by making all process memory mutually visible.

7. A process can permanently relinquish root privileges by setting real, effective, and saved UIDs to an unprivileged UID with `setresuid(target, target, target)`, and doing the same for GIDs with `setresgid` in a full production design. It should also clear supplementary groups and drop capabilities. The operation must be irreversible because any later path that can regain root becomes a privilege-escalation target. If attacker-controlled input can influence a code path after a reversible drop, the attacker can try to trigger a regain operation. A permanent drop means that even successful control-flow hijacking is constrained by the unprivileged kernel identity.

8. Observation indicators for a successful drop include `geteuid()` returning the unprivileged UID, `/proc/<pid>/status` showing expected real/effective/saved UID fields, `CapEff` being zero in a capability-aware design, failed attempts to open root-only files, and failed attempts to regain root with `setuid(0)`. Tracing with `strace` can show the actual `setresuid` syscall and its return value. Process tools such as `ps -o pid,user,euser,ruid,suid,cmd -p <pid>` can also show identity changes while the backend is alive.

9. If a process unintentionally retained elevated privileges, an attacker could use a memory corruption bug, input validation bug, command injection, path traversal, or unsafe helper execution to read or modify protected files, create privileged sockets, alter system state, install persistence, steal credentials, or tamper with logs. Even a small bug becomes more dangerous when the process still has root permissions or sensitive descriptors. Privilege separation reduces the reward of compromise by limiting what the attacked component can do after exploitation.

10. Clearing sensitive memory after authentication is required because secrets can remain in process memory long after their logical use is finished. Passwords may be exposed through core dumps, debugging tools, swap, crash reports, use-after-free bugs, or later heap reuse. If the backend authenticates correctly but leaves the password in shared memory, a later bug in either process could disclose it. Clearing the buffer shortens the lifetime of the secret and reduces the amount of evidence left behind for accidental or malicious disclosure.

11. Standard memory clearing functions can be unreliable because the C abstract machine allows an optimizing compiler to remove writes that have no observable effect. If a buffer is zeroed with `memset` immediately before the buffer goes out of scope or is freed, the compiler may determine that no later defined program behavior reads those zeros and eliminate the call as dead-store elimination. That behavior is legal under ordinary C optimization rules, even though it conflicts with the security intention. The compiler sees a dead write; the security engineer sees deliberate erasure.

12. Explicit memory primitives mitigate this risk by creating an operation the compiler must preserve. On glibc, `explicit_bzero` is intended for this purpose. Other platforms offer `memset_s`, `explicit_memset`, `SecureZeroMemory`, or carefully written volatile-pointer loops. This project uses `explicit_bzero` when available and falls back to a volatile byte loop. The goal is not cryptographic magic; it is to make the erase operation part of observable execution so optimized builds still wipe the password buffer.

## Task 2: User Space Malware Analysis Sandbox

`Sandbox.c` implements a small process-control sandbox controller. The controller is the trusted parent. The untrusted program is the child. The child is created with `fork`, assigned basic resource limits, and replaced with the target executable through `execve`. After `execve`, the untrusted program is not linked to, called by, or trusted by the monitor. It does not participate in its own monitoring or termination. The parent observes from outside through `/proc`, `waitpid`, timers, mutex-protected state, and POSIX threads.

The monitor has two concurrent worker threads. The time monitor checks elapsed wall-clock time using `CLOCK_MONOTONIC`. If the child exceeds `SANDBOX_TIME_LIMIT`, it sends `SIGTERM`, waits briefly, and then sends `SIGKILL` if the process has not exited. The resource monitor reads `/proc/<pid>/status` and extracts `VmRSS`. If resident memory exceeds `SANDBOX_RSS_LIMIT_KB`, it sends `SIGKILL`. The child is placed in its own process group, and policy signals are sent to that process group rather than only to one PID. This means simple child-created helper processes are cleaned up with the sandboxed process. The main parent thread waits with `waitpid`, records completion, checks for remaining process-group members, and joins the monitor threads. A `pthread_mutex_t` protects shared state such as `finished`, `killed`, and log writes. This avoids races where monitors continue acting on a process that has already exited or where log lines interleave into unreadable output.

The sample test binaries are harmless but representative. `quick_exit` exits normally. `sleeper` exceeds a short wall-clock time limit. `cpu_hog` spins forever and is terminated by the time monitor. `memory_hog` repeatedly allocates memory and is terminated by the RSS monitor when the configured threshold is low enough. These test binaries prove that termination is enforced by the parent and not by cooperation from the untrusted program.

### Sandbox Verification

Build:

```sh
make
```

Normal completion:

```sh
rm -f sandbox.log
./Sandbox ./test_binaries/quick_exit
cat sandbox.log
```

Expected result: the child exits with code `0` and `killed_by_policy=no`.

Time policy:

```sh
rm -f sandbox.log
SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/sleeper
cat sandbox.log
```

Expected result: a policy line shows signal `15` for time limit exceeded, followed by child termination by signal.

Memory policy:

```sh
rm -f sandbox.log
SANDBOX_RSS_LIMIT_KB=12000 ./Sandbox ./test_binaries/memory_hog
cat sandbox.log
```

Expected result: repeated RSS observations followed by signal `9` for RSS limit exceeded.

### Analysis and Observation Questions

Parent-child isolation matters because the parent and child have separate address spaces and separate execution states. The parent can observe and control the child without trusting the child to report honestly. If the child hangs, loops, allocates memory, or ignores ordinary program logic, the parent can still send a signal. If the untrusted binary crashes, the parent remains alive and can record the event. This is the basic reason sandboxes are controllers rather than libraries inside the untrusted process.

Race-free shared state matters because the supervisor uses several threads. One thread waits for process exit while another watches time and another watches resource usage. Without a mutex, two monitors might both decide to kill the child, one monitor might log after cleanup, or a stale value of `finished` might make a thread act on a recycled PID. The state in this project is small and protected by `pthread_mutex_t`. That is enough for the coursework goal: a clear concurrency model where shared flags and log writes are synchronized.

Forced termination is required because untrusted code cannot be assumed to cooperate. A malicious or broken program may ignore internal checks, never return from a function, catch `SIGTERM`, or intentionally consume CPU and memory. The supervisor therefore uses kernel signals. `SIGTERM` gives a process a chance to shut down for time-limit violations. `SIGKILL` is then used as the non-cooperative fallback because it cannot be caught or ignored. For memory-limit violations, the controller sends `SIGKILL` immediately because continuing allocation can destabilize the host.

### Task 2 Investigation Answers

1. Process-level isolation is preferred over in-process containment for executing untrusted binaries because an ordinary C process is not a strong internal security boundary. If untrusted code runs inside the same process as the monitor, it shares the same address space, heap, stack, file descriptors, signal handlers, and usually the same process credentials. A bug or intentional exploit can corrupt monitor memory, change function pointers, overwrite state variables, or bypass checks by directly modifying the values the monitor depends on. In contrast, a separate child process gives the kernel a clear object to control. The monitor can remain outside the untrusted address space and use kernel interfaces such as `waitpid`, `/proc`, resource limits, and signals. This project follows that model: `Sandbox.c` never links the unsafe binary into itself. It creates a child with `fork`, then the child becomes the unsafe binary through `execve`.

2. The parent-child process model supports monitoring and enforcement because the parent retains the child's PID and can observe the child from outside. After `fork`, the parent and child are separate processes. After `execve`, the child no longer contains the sandbox program image; it contains the target binary. The parent can still call `waitpid` to learn how the child exited, read `/proc/<pid>/status` to inspect memory use, and call `kill` to send policy-enforcement signals. This means the parent can impose rules even if the child is buggy, hostile, or stuck. In the implementation, the main parent thread waits for exit while monitor threads check elapsed time and resident memory. If a limit is broken, the monitor sends a signal to the child's process group.

3. When untrusted code is executed via `execve`, the security assumption changes from "the child is a copy of the parent program" to "the child is now a different executable image." The old code, stack, heap, and most process image state are replaced. This is useful because the sandbox controller's code is not present inside the untrusted executable after `execve`. However, some attributes survive across `execve`, including PID, open file descriptors without close-on-exec, resource limits, current working directory, process group, UID/GID credentials, and environment variables. Therefore, the sandbox must be careful about what it lets the child inherit. This project gives the child a minimal environment, applies resource limits before `execve`, and isolates it into its own process group. A production sandbox would also close unnecessary descriptors, apply namespaces, seccomp, cgroups, and filesystem restrictions.

4. CPU usage and execution time can be measured externally in several ways. Wall-clock execution time can be measured by the parent using `clock_gettime(CLOCK_MONOTONIC)` before launching the child and comparing the current monotonic time during monitoring. CPU time can be observed with `wait4` or `getrusage` after the child exits, or by reading `/proc/<pid>/stat` while it is running and calculating user/system CPU ticks. This project uses monotonic wall-clock time for enforcement because it catches both CPU-bound loops and sleeping or blocking programs. It also applies `RLIMIT_CPU` in the child as an additional kernel-level CPU guard. For memory, the resource monitor reads `VmRSS` from `/proc/<pid>/status`, which demonstrates external observation without cooperation from the target.

5. Time-based enforcement must be independent of the monitored process's cooperation because malicious or broken code cannot be trusted to check timers, return from functions, or call cleanup routines. If the unsafe binary were responsible for stopping itself, an attacker could remove the check, block before the check, catch ordinary application-level events, sleep forever, or deliberately lie about progress. The parent must therefore use an independent clock and a separate execution context. In `Sandbox.c`, the time-monitoring thread runs in the parent process. It compares elapsed time against `SANDBOX_TIME_LIMIT` and sends `SIGTERM` followed by `SIGKILL` if necessary. The child does not take part in this decision.

6. Signals are the operating-system mechanism used here to enforce termination policies. A signal is delivered by the kernel to a process or process group. `SIGTERM` requests termination and may be caught or handled by the target. It is useful when the sandbox wants to allow graceful shutdown. `SIGKILL` cannot be caught, blocked, or ignored, so it is used as the final enforcement mechanism. This project sends signals to the child's process group rather than only to the direct child PID. That refinement matters because an untrusted program may create helper children. Killing only the original PID could leave descendant processes running. Process-group signaling gives the controller a stronger cleanup mechanism for simple process trees.

7. Concurrency is required in a sandbox monitoring system because different monitoring activities happen at the same time as the target runs. One activity may wait for child exit, another may monitor wall-clock time, and another may monitor resource use. If the supervisor used only one blocking thread, it might be stuck in `waitpid` while memory rises rapidly, or it might be polling `/proc` while missing prompt process termination. In this implementation, the main thread waits for the child, a time thread enforces the wall-clock limit, and a resource thread logs RSS and enforces memory policy. This reflects the assignment requirement that the supervising process use several pthreads for concurrent monitoring.

8. Shared state between monitoring threads can introduce subtle race conditions because the threads read and write common flags such as `finished`, `killed`, and `exit_status`. If one thread sets `finished` while another thread reads it without synchronization, the C program has a data race. The result is undefined behavior, not merely a stale value. Race conditions can also cause duplicate signals, misleading logs, cleanup after resources have been closed, or action against a PID that has already exited. `Sandbox.c` uses a `pthread_mutex_t` to protect shared flags and log writes. This makes the monitor state defensible: one thread records completion, other threads observe that completion consistently, and log entries remain readable.

9. The C language memory model requires atomic operations or proper synchronization primitives rather than `volatile` variables for synchronization. `volatile` tells the compiler that an object may be accessed in ways the compiler cannot fully see, so it should not remove or combine some accesses. It does not create inter-thread happens-before relationships, does not make compound operations atomic, and does not provide mutex-style mutual exclusion. For pthread programs, the standard solution is to use `pthread_mutex_lock` and `pthread_mutex_unlock`, condition variables, or C11 atomics. This project uses a mutex, which is appropriate for its small amount of shared state and also protects the log file from interleaved writes.

10. Timing channels or side effects could be used to bypass or weaken sandbox restrictions when the sandbox does not isolate all observable resources. A process might encode information in CPU usage, memory pressure, file metadata changes, exit timing, process creation patterns, or attempted network behavior. If the sandbox only measures one process, a target might fork children or use helper programs to continue activity after the parent exits. If filesystem and network access are not restricted, a sample might write evidence elsewhere or exfiltrate data before a time limit triggers. This is why the refined sandbox uses process groups, but also why the report states that this is an educational user-space sandbox rather than a complete malware containment system.

11. Understanding these limitations is critical in real-world malware analysis because a sandbox can create a false sense of safety. Malware often behaves differently when it detects monitoring, virtualization, unusual timing, restricted resources, or analysis tools. A weak sandbox may allow host compromise, credential theft, persistence, network scanning, or destruction of evidence. Even if it prevents direct compromise, it may miss behavior because the sample waits, forks, checks side channels, or triggers only under specific environmental conditions. Security researchers therefore combine process supervision with stronger isolation mechanisms such as virtual machines, containers, namespaces, cgroups, seccomp filters, network controls, snapshots, and careful evidence handling. The coursework implementation demonstrates the process-control foundation, while the limitations explain why production analysis needs additional layers.

This sandbox is educational and user-space only. It demonstrates process management, resource observation, signals, and pthread-based monitoring. It is not a complete malware containment system. Real malware analysis environments normally add virtual machines or containers, filesystem isolation, network isolation, seccomp filters, namespaces, cgroups, audit logging, snapshot rollback, and strict handling of analysis artifacts. The important design principle remains the same: the untrusted process is the subject being observed, while the monitor stays outside and retains the authority to stop it.

### Extended Design Discussion

The controller deliberately uses `execve` instead of `system` or `popen`. `system` would introduce a shell between the sandbox and the target, which would complicate attribution and create command-line parsing risks. `execve` replaces the child image directly with the chosen binary and an explicit argument vector. It also allows the controller to provide a small environment rather than inheriting every variable from the parent. Environment variables can affect dynamic linking, temporary directories, language runtimes, proxies, and tool behavior, so a real sandbox should be careful about them. This project keeps only a minimal `PATH` and `MALLOC_ARENA_MAX` setting for the child.

The parent also sets resource limits in the child before `execve`. This is a useful belt-and-braces measure: `RLIMIT_CPU` and `RLIMIT_AS` are kernel-level constraints that still apply after the executable image changes. However, resource limits alone are not the complete monitoring solution requested by the task. The assignment requires external observation and forced termination by the supervising process. For that reason, the parent continues to read `/proc`, track elapsed wall time, and send signals. This separation is important in malware analysis because the investigator wants independent evidence of behavior, not just a final exit code from a process that may be hostile.

The time monitor uses wall-clock time rather than only CPU time. This catches programs that sleep forever, wait on input, or block on an operation. CPU limits are useful for spin loops, but they do not stop a binary that consumes almost no CPU while still tying up the analysis session. The memory monitor reads resident set size, which is not a perfect measure of every form of memory pressure, but it is easy to observe externally and demonstrates the operating-system interface clearly. In stronger designs, cgroups would provide more reliable accounting across process trees, including child processes created by the sample. This coursework version focuses on the requested user-space parent-child design.

Signal choice is also intentional. `SIGTERM` is used first for time violations because a well-behaved program may flush logs or exit cleanly. If it does not exit, `SIGKILL` follows. `SIGKILL` is the enforcement mechanism of last resort because the process cannot catch, block, or ignore it. Memory violations use `SIGKILL` immediately because a process that is rapidly allocating memory can make the host unstable. The log records which signal was sent and why, giving the analyst an audit trail for the termination decision.

The project uses a mutex even though the shared state is small. Without locking, the main thread could set `finished` while a monitor thread reads it concurrently, which is a data race in C and undefined behavior. Log writes from several threads can also interleave. The mutex makes the program boring in the right way: state transitions are explicit, and the evidence in `sandbox.log` stays readable. Race-free monitoring is not only about program correctness; it is also about forensic trust. If the log is garbled or if a monitor kills after the child has already been reaped, the analysis result becomes harder to defend.

The test binaries are intentionally simple because the goal is to verify the operating-system mechanisms. `quick_exit` establishes the normal baseline. `sleeper` proves that wall-clock supervision works even when the target is not consuming CPU. `cpu_hog` proves that an infinite loop does not require cooperation from the target to stop. `memory_hog` proves that external resource observation can trigger a policy decision. Together they create a small but complete demonstration set: normal execution, time abuse, CPU abuse, and memory abuse.

There are still residual risks. The sandbox does not isolate filesystem access, network access, child process trees, system calls, or kernel attack surface. A real untrusted malware sample should not be run on a normal host with only this controller. The safe operational model is a disposable VM or container with no valuable credentials, no production network access, snapshots, and strict export handling. The value of this program is that it shows the core process-control pattern used inside larger systems: start the target as a child, keep the monitor outside it, observe through kernel interfaces, synchronize supervisor threads carefully, and terminate by policy rather than by trust.

### Evidence Checklist

For the privilege-separation task, the evidence should include the build output, a successful `./Frontend alice` interactive run or `./Frontend alice wonderland` scripted run, a failed password run, an invalid username run, and `strace` lines showing `execve`, `sendmsg`, `recvmsg`, `setresgid`, `setresuid`, and `geteuid`. The runtime output should include the backend PID, peer credentials from `SO_PEERCRED`, the post-drop `geteuid`, and the `/proc/self/status` `Uid:`, `Gid:`, and `CapEff:` lines.

For the sandbox task, the evidence should include `sandbox.log` after each test binary. The log should show `quick_exit` completing normally, `sleeper` being terminated after the configured time limit, `cpu_hog` being terminated by policy, and `memory_hog` being killed when observed RSS exceeds the configured threshold. The supplied `logs/sample_sandbox.log` demonstrates the expected shape of this evidence, but the strongest submission evidence is a fresh log generated on the Linux machine used for marking or demonstration.

### Execution Evidence Plan

The practical evidence for Task 1 should show both normal and hostile paths. A successful run demonstrates that the two executable files can cooperate correctly: `Frontend` starts, creates a private socket pair, places the password into shared memory, forks, and executes `Backend`. The backend output should then identify its PID and its peer credentials. That peer credential line matters because it proves the backend is not simply trusting a string sent by the frontend. It is asking the kernel for the UID, GID, and PID associated with the connected socket. After that, the backend should print its dropped identity and `/proc/self/status` lines. These lines are the runtime observation required by the task. They are more convincing than a source-code claim because they show the identity of the running process after privilege-management calls have completed.

The failed runs are just as important. `./Frontend 'bad/user' wonderland` shows frontend-side input filtering, while `./Frontend alice wrong-password` shows backend-side denial. Security must not depend only on the exposed process behaving correctly, so the backend repeats validation of lengths and username characters. In a demonstration, a marker should be able to see that invalid data is not simply passed through to a privileged decision. A useful extra test is to modify the frontend temporarily or use a small separate client to send an invalid request structure; the backend validation path should still return `DENY`. That observation supports the attack-resistance requirement.

The strongest low-level evidence is a syscall trace. Running `strace -f` against `Frontend` should show process creation and image replacement with `execve("./Backend", ...)`. It should also show `sendmsg` and `recvmsg`, which are the system calls used for UNIX-domain descriptor passing. The trace should show `setresgid` and the required `setresuid` in the backend process. Finally, a disassembly check such as `objdump -d Backend | grep -A20 drop_privileges` or `objdump -T Backend | grep setresuid` can be used to demonstrate that the compiled backend contains a call path to the privilege-dropping function. Disassembly is not a substitute for execution, but it is useful supporting evidence for the assignment requirement that mentions disassembly.

For Task 2, the evidence should demonstrate that each test binary is controlled externally. `quick_exit` establishes that the sandbox does not kill every child by default. It should exit normally and produce `killed_by_policy=no`. `sleeper` demonstrates wall-clock enforcement because it consumes little CPU but still exceeds the time limit. `cpu_hog` demonstrates a non-cooperative process that keeps executing until the parent enforces policy. `memory_hog` demonstrates resource observation, because the parent logs rising RSS values from `/proc` and then kills the process when the threshold is exceeded. In all cases, the untrusted test binary does not call monitor functions, does not check the policy, and does not voluntarily terminate because of sandbox logic. The evidence therefore supports the central claim: the parent imposes control.

The log file is part of the security argument. A good log should include the child PID, target executable name, configured limits, repeated monitoring observations, signal decisions, final exit status, and whether policy killed the target. If a child creates descendants, the process-group refinement means the parent sends signals to the group rather than only to the original PID. That does not make the sandbox production-grade, but it avoids an obvious failure where helper processes remain after the direct child exits. The practical demonstration should therefore keep `sandbox.log` after the test run and submit it with the source code.

### Limitations and Professional Use

This project intentionally stays within the assignment boundary: C programming, processes, pthreads, UNIX IPC, shared memory, `/proc`, resource observation, and signals. It does not claim to be a complete containment product. A real malware analysis lab would normally run samples inside disposable virtual machines or containers with network controls, filesystem snapshots, non-persistent disks, fake services, and strict artifact handling. Linux namespaces can isolate mounts, PIDs, users, IPC objects, UTS names, and networks. Cgroups can account for and limit CPU, memory, process counts, and I/O across whole process trees. Seccomp-BPF can restrict system calls. These stronger mechanisms would reduce the residual risks discussed in the investigation answers.

However, the project is still useful because these advanced systems are built on the same basic operating-system ideas. A controller starts an untrusted program, gives it only selected resources, observes it from outside, records behavior, and terminates it when policy is violated. The privilege-separation task shows the same principle from the authentication side: split exposed parsing from sensitive decision-making, minimize shared state, verify identities through the kernel, drop privileges permanently, and erase secrets after use. Together, the two tasks demonstrate the module outcomes: understanding C/Linux behavior, designing software from a specification, explaining the operating system's role, and building programs that use both processes and threads with controlled shared data.

## References

Kerrisk, M. (2010) *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*. San Francisco: No Starch Press.

Stevens, W. R. and Rago, S. A. (2013) *Advanced Programming in the UNIX Environment*. 3rd edn. Boston: Addison-Wesley.

Silberschatz, A., Galvin, P. B. and Gagne, G. (2018) *Operating System Concepts*. 10th edn. Hoboken: Wiley.

Seacord, R. C. (2013) *Secure Coding in C and C++*. 2nd edn. Boston: Addison-Wesley.

Saltzer, J. H. and Schroeder, M. D. (1975) 'The protection of information in computer systems', *Proceedings of the IEEE*, 63(9), pp. 1278-1308.

Miller, R. S. (2006) *Security in Plan 9*. Available at: https://9p.io/sys/doc/auth.html

Linux man-pages project (2026) `fork(2)`, `execve(2)`, `setresuid(2)`, `setresgid(2)`, `socketpair(2)`, `unix(7)`, `mmap(2)`, `shm_open(3)`, `proc(5)`, `pthread_create(3)`, `kill(2)`, `waitpid(2)`. Available at: https://man7.org/linux/man-pages/

The Open Group (2018) *The Open Group Base Specifications Issue 7, 2018 edition*. Available at: https://pubs.opengroup.org/onlinepubs/9699919799/
