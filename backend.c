/* Backend.c */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOCKET_PATH "/tmp/privsep_auth.sock"
#define MAGIC 0x41555448u
#define OP_VALIDATE 1u
#define MAX_USER 32
#define MAX_PASS 128
#define MAX_SHM_NAME 64

struct auth_request {
    uint32_t magic;
    uint32_t op;
    uid_t owner_uid;
    size_t password_len;
    char username[MAX_USER];
    char shm_name[MAX_SHM_NAME];
};

struct auth_response {
    uint32_t magic;
    uint32_t ok;
    char message[96];
};

static void secure_bzero(void *ptr, size_t len) {
#if defined(__GLIBC__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

static uint64_t fnv1a64(const unsigned char *data, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int constant_time_u64_eq(uint64_t a, uint64_t b) {
    uint64_t x = a ^ b;
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    return (int)((x ^ 1) & 1);
}

static uid_t target_unprivileged_uid(void) {
    const char *name = getenv("AUTH_DROP_USER");
    if (name && *name) {
        struct passwd *pw = getpwnam(name);
        if (!pw) {
            fprintf(stderr, "AUTH_DROP_USER not found\n");
            exit(1);
        }
        return pw->pw_uid;
    }

    uid_t ruid = getuid();
    if (ruid != 0) return ruid;

    struct passwd *pw = getpwnam("nobody");
    if (pw) return pw->pw_uid;

    return 65534;
}

static void drop_privileges_permanently(void) {
    uid_t target = target_unprivileged_uid();

    if (setresgid(target, target, target) != 0) {
        perror("setresgid");
        exit(1);
    }

    if (setresuid(target, target, target) != 0) {
        perror("setresuid");
        exit(1);
    }

    if (seteuid(0) == 0) {
        fprintf(stderr, "fatal: privilege drop was reversible\n");
        exit(1);
    }

    printf("runtime uid check: ruid=%ld euid=%ld\n",
           (long)getuid(), (long)geteuid());
}

static int recv_full(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_full(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int get_peer_uid(int fd, uid_t *uid_out) {
    struct ucred cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return -1;
    }

    *uid_out = cred.uid;
    return 0;
}

static int validate_password(const char *username, const char *password, size_t len) {
    if (strcmp(username, "alice") == 0) {
        uint64_t expected = fnv1a64((const unsigned char *)"CorrectHorseBatteryStaple!", 26);
        uint64_t actual = fnv1a64((const unsigned char *)password, len);
        return constant_time_u64_eq(actual, expected);
    }

    if (strcmp(username, "bob") == 0) {
        uint64_t expected = fnv1a64((const unsigned char *)"S3cure-Bob-Password", 19);
        uint64_t actual = fnv1a64((const unsigned char *)password, len);
        return constant_time_u64_eq(actual, expected);
    }

    return 0;
}

static void handle_client(int client_fd) {
    struct auth_request req;
    struct auth_response resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    resp.magic = MAGIC;

    if (recv_full(client_fd, &req, sizeof(req)) != 0) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "bad request framing");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    uid_t peer_uid;
    if (get_peer_uid(client_fd, &peer_uid) != 0) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "cannot verify peer credentials");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    if (req.magic != MAGIC || req.op != OP_VALIDATE) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "rejected: not a validation request");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    if (req.owner_uid != peer_uid) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "rejected: uid mismatch");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    if (req.password_len == 0 || req.password_len > MAX_PASS ||
        req.username[MAX_USER - 1] != '\0' ||
        req.shm_name[0] != '/' ||
        req.shm_name[MAX_SHM_NAME - 1] != '\0') {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "rejected: invalid fields");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    int shm_fd = shm_open(req.shm_name, O_RDWR, 0);
    if (shm_fd < 0) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "cannot open shared password buffer");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    char *password = mmap(NULL, MAX_PASS, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (password == MAP_FAILED) {
        resp.ok = 0;
        snprintf(resp.message, sizeof(resp.message), "cannot map shared password buffer");
        send_full(client_fd, &resp, sizeof(resp));
        return;
    }

    int ok = validate_password(req.username, password, req.password_len);
    secure_bzero(password, MAX_PASS);
    munmap(password, MAX_PASS);

    resp.ok = ok ? 1u : 0u;
    snprintf(resp.message, sizeof(resp.message), "%s", ok ? "authentication accepted" : "authentication rejected");
    send_full(client_fd, &resp, sizeof(resp));
}

int main(void) {
    printf("backend startup uid check: ruid=%ld euid=%ld\n",
           (long)getuid(), (long)geteuid());

    drop_privileges_permanently();

    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    unlink(SOCKET_PATH);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    chmod(SOCKET_PATH, 0600);

    if (listen(server_fd, 16) != 0) {
        perror("listen");
        close(server_fd);
        unlink(SOCKET_PATH);
        return 1;
    }

    for (;;) {
        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept4");
            break;
        }

        handle_client(client_fd);
        close(client_fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}