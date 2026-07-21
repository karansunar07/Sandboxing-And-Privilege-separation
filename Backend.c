#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define IPC_FD 3
#define MAX_USER 32
#define MAX_PASS 128
#define SHM_SIZE 4096

struct auth_request {
    char username[MAX_USER];
    uint32_t password_len;
};

struct auth_reply {
    int ok;
    char message[128];
};

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void explicit_bzero_local(void *ptr, size_t len) {
#if defined(__GLIBC__) && defined(_DEFAULT_SOURCE)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

static int receive_fd_with_request(int sock, int *fd, struct auth_request *req) {
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {
        .iov_base = req,
        .iov_len = sizeof(*req)
    };
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    ssize_t n = recvmsg(sock, &msg, 0);
    if (n != (ssize_t)sizeof(*req)) {
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }
    memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
    return 0;
}

static int valid_request(const struct auth_request *req) {
    size_t user_len = strnlen(req->username, MAX_USER);
    if (user_len == 0 || user_len >= MAX_USER) {
        return 0;
    }
    if (req->password_len == 0 || req->password_len > MAX_PASS) {
        return 0;
    }
    for (size_t i = 0; i < user_len; i++) {
        if (!isalnum((unsigned char)req->username[i]) &&
            req->username[i] != '_' &&
            req->username[i] != '-') {
            return 0;
        }
    }
    return 1;
}

static void unprivileged_identity(uid_t *uid, gid_t *gid) {
    struct passwd *pw = getpwnam("nobody");
    if (pw != NULL) {
        *uid = pw->pw_uid;
        *gid = pw->pw_gid;
        return;
    }
    *uid = getuid();
    *gid = getgid();
}

static void drop_privileges_permanently(void) {
    uid_t target_uid;
    gid_t target_gid;

    if (geteuid() == 0) {
        unprivileged_identity(&target_uid, &target_gid);
        if (setgroups(0, NULL) == -1) {
            die("setgroups");
        }
    } else {
        target_uid = getuid();
        target_gid = getgid();
    }

    if (setresgid(target_gid, target_gid, target_gid) == -1) {
        die("setresgid");
    }

    if (setresuid(target_uid, target_uid, target_uid) == -1) {
        die("setresuid");
    }

    if (geteuid() != target_uid || getegid() != target_gid) {
        fprintf(stderr, "runtime check failed: euid=%ld egid=%ld expected=%ld/%ld\n",
                (long)geteuid(), (long)getegid(), (long)target_uid, (long)target_gid);
        exit(EXIT_FAILURE);
    }

    if (setuid(0) == 0) {
        fprintf(stderr, "runtime check failed: process regained root\n");
        exit(EXIT_FAILURE);
    }
}

static void print_proc_status(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        perror("open /proc/self/status");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "Uid:", 4) == 0 ||
            strncmp(line, "Gid:", 4) == 0 ||
            strncmp(line, "CapEff:", 7) == 0) {
            fputs(line, stdout);
        }
    }
    fclose(fp);
}

int main(void) {
    printf("Backend pid=%ld starting euid=%ld\n", (long)getpid(), (long)geteuid());

    struct auth_request req;
    int shm_fd = -1;
    if (receive_fd_with_request(IPC_FD, &shm_fd, &req) == -1) {
        die("recvmsg auth request");
    }

    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(IPC_FD, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) == -1) {
        die("getsockopt SO_PEERCRED");
    }
    printf("Backend peer pid=%ld uid=%ld gid=%ld\n",
           (long)peer.pid, (long)peer.uid, (long)peer.gid);

    drop_privileges_permanently();
    printf("Backend dropped privileges; geteuid=%ld\n", (long)geteuid());
    print_proc_status();

    struct auth_reply reply;
    memset(&reply, 0, sizeof(reply));

    if (!valid_request(&req)) {
        reply.ok = 0;
        snprintf(reply.message, sizeof(reply.message), "request validation failed");
        send(IPC_FD, &reply, sizeof(reply), 0);
        close(shm_fd);
        return EXIT_FAILURE;
    }

    char *password = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (password == MAP_FAILED) {
        die("mmap password");
    }

    if (strnlen(password, req.password_len + 1) != req.password_len) {
        reply.ok = 0;
        snprintf(reply.message, sizeof(reply.message), "password buffer length mismatch");
    } else if (strcmp(req.username, "alice") == 0 &&
               req.password_len == strlen("wonderland") &&
               memcmp(password, "wonderland", req.password_len) == 0) {
        reply.ok = 1;
        snprintf(reply.message, sizeof(reply.message), "validated after privilege drop");
    } else {
        reply.ok = 0;
        snprintf(reply.message, sizeof(reply.message), "invalid credential");
    }

    explicit_bzero_local(password, SHM_SIZE);
    munmap(password, SHM_SIZE);
    close(shm_fd);

    if (send(IPC_FD, &reply, sizeof(reply), 0) != (ssize_t)sizeof(reply)) {
        die("send auth reply");
    }
    return reply.ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
