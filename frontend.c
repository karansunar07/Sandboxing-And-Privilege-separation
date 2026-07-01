/* Frontend.c */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SOCKET_PATH "/tmp/privsep_auth.sock"
#define BACKEND_PATH "./Backend"
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

static void trim_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n') s[n - 1] = '\0';
}

static int read_password(char *buf, size_t cap) {
    struct termios oldt, newt;

    if (tcgetattr(STDIN_FILENO, &oldt) != 0) return -1;
    newt = oldt;
    newt.c_lflag &= (tcflag_t)~ECHO;

    printf("Password: ");
    fflush(stdout);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) return -1;

    char *ok = fgets(buf, (int)cap, stdin);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    printf("\n");

    if (!ok) return -1;
    trim_newline(buf);
    return 0;
}

static pid_t start_backend_if_needed(void) {
    if (access(SOCKET_PATH, F_OK) == 0) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        char *const argv[] = { (char *)BACKEND_PATH, NULL };
        char *const envp[] = { NULL };
        execve(BACKEND_PATH, argv, envp);
        perror("execve Backend");
        _exit(127);
    }

    for (int i = 0; i < 50; i++) {
        if (access(SOCKET_PATH, F_OK) == 0) return pid;
        usleep(100000);
    }

    fprintf(stderr, "backend socket did not appear\n");
    return pid;
}

static int connect_backend(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int main(void) {
    pid_t backend_pid = start_backend_if_needed();
    (void)backend_pid;

    char username[MAX_USER];
    char password[MAX_PASS];

    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));

    printf("Username: ");
    fflush(stdout);

    if (!fgets(username, sizeof(username), stdin)) {
        fprintf(stderr, "failed to read username\n");
        return 1;
    }

    trim_newline(username);

    if (read_password(password, sizeof(password)) != 0) {
        fprintf(stderr, "failed to read password\n");
        return 1;
    }

    size_t password_len = strlen(password);
    if (password_len == 0 || password_len >= MAX_PASS) {
        fprintf(stderr, "invalid password length\n");
        secure_bzero(password, sizeof(password));
        return 1;
    }

    char shm_name[MAX_SHM_NAME];
    snprintf(shm_name, sizeof(shm_name), "/auth_%ld_%ld",
             (long)getpid(), (long)time(NULL));

    int shm_fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (shm_fd < 0) {
        perror("shm_open");
        secure_bzero(password, sizeof(password));
        return 1;
    }

    if (ftruncate(shm_fd, MAX_PASS) != 0) {
        perror("ftruncate");
        shm_unlink(shm_name);
        close(shm_fd);
        secure_bzero(password, sizeof(password));
        return 1;
    }

    char *shared_password = mmap(NULL, MAX_PASS, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (shared_password == MAP_FAILED) {
        perror("mmap");
        shm_unlink(shm_name);
        secure_bzero(password, sizeof(password));
        return 1;
    }

    memcpy(shared_password, password, password_len);
    secure_bzero(password, sizeof(password));

    struct auth_request req;
    memset(&req, 0, sizeof(req));
    req.magic = MAGIC;
    req.op = OP_VALIDATE;
    req.owner_uid = getuid();
    req.password_len = password_len;
    strncpy(req.username, username, sizeof(req.username) - 1);
    strncpy(req.shm_name, shm_name, sizeof(req.shm_name) - 1);

    int fd = connect_backend();
    if (fd < 0) {
        perror("connect backend");
        secure_bzero(shared_password, MAX_PASS);
        munmap(shared_password, MAX_PASS);
        shm_unlink(shm_name);
        return 1;
    }

    struct auth_response resp;
    memset(&resp, 0, sizeof(resp));

    if (send_full(fd, &req, sizeof(req)) != 0 ||
        recv_full(fd, &resp, sizeof(resp)) != 0 ||
        resp.magic != MAGIC) {
        fprintf(stderr, "authentication IPC failed\n");
        close(fd);
        secure_bzero(shared_password, MAX_PASS);
        munmap(shared_password, MAX_PASS);
        shm_unlink(shm_name);
        return 1;
    }

    close(fd);
    secure_bzero(shared_password, MAX_PASS);
    munmap(shared_password, MAX_PASS);
    shm_unlink(shm_name);

    printf("%s\n", resp.message);
    return resp.ok ? 0 : 2;
}