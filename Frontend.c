#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define BACKEND_PATH "./Backend"
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

static int valid_username(const char *user) {
    size_t n = strlen(user);
    if (n == 0 || n >= MAX_USER) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)user[i]) && user[i] != '_' && user[i] != '-') {
            return 0;
        }
    }
    return 1;
}

static int read_password(char *buf, size_t buflen) {
    struct termios old_term, new_term;

    if (tcgetattr(STDIN_FILENO, &old_term) == -1) {
        return -1;
    }
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);

    fputs("Password: ", stderr);
    fflush(stderr);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) == -1) {
        return -1;
    }
    if (fgets(buf, (int)buflen, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    fputc('\n', stderr);

    size_t n = strcspn(buf, "\n");
    buf[n] = '\0';
    return 0;
}

static void send_fd_with_request(int sock, int fd, const struct auth_request *req) {
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {
        .iov_base = (void *)req,
        .iov_len = sizeof(*req)
    };
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock, &msg, 0) != (ssize_t)sizeof(*req)) {
        die("sendmsg");
    }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <username> [password]\n", argv[0]);
        fprintf(stderr, "if password is omitted, it is read without terminal echo\n");
        fprintf(stderr, "demo credential accepted by Backend: alice wonderland\n");
        return EXIT_FAILURE;
    }

    if (!valid_username(argv[1])) {
        fprintf(stderr, "Frontend rejected invalid username before IPC\n");
        return EXIT_FAILURE;
    }

    char password_input[MAX_PASS + 2];
    memset(password_input, 0, sizeof(password_input));
    if (argc == 3) {
        if (strnlen(argv[2], MAX_PASS + 1) > MAX_PASS) {
            fprintf(stderr, "Frontend rejected invalid password length\n");
            return EXIT_FAILURE;
        }
        strncpy(password_input, argv[2], sizeof(password_input) - 1);
        explicit_bzero_local(argv[2], strlen(argv[2]));
    } else if (read_password(password_input, sizeof(password_input)) == -1) {
        die("read password");
    }

    size_t pass_len = strnlen(password_input, MAX_PASS + 1);
    if (pass_len == 0 || pass_len > MAX_PASS) {
        fprintf(stderr, "Frontend rejected invalid password length\n");
        explicit_bzero_local(password_input, sizeof(password_input));
        return EXIT_FAILURE;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == -1) {
        die("socketpair");
    }

    char shm_name[64];
    snprintf(shm_name, sizeof(shm_name), "/privsep_auth_password_%ld", (long)getpid());

    int shm_fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (shm_fd == -1) {
        die("shm_open");
    }
    shm_unlink(shm_name);

    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        die("ftruncate");
    }

    char *password = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (password == MAP_FAILED) {
        die("mmap");
    }
    memcpy(password, password_input, pass_len);
    password[pass_len] = '\0';
    explicit_bzero_local(password_input, sizeof(password_input));

    pid_t child = fork();
    if (child == -1) {
        die("fork");
    }

    if (child == 0) {
        close(sv[0]);
        if (dup2(sv[1], IPC_FD) == -1) {
            die("dup2");
        }
        close(sv[1]);

        char *backend_argv[] = { "Backend", NULL };
        char *backend_envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(BACKEND_PATH, backend_argv, backend_envp);
        die("execve Backend");
    }

    close(sv[1]);

    struct auth_request req;
    memset(&req, 0, sizeof(req));
    strncpy(req.username, argv[1], sizeof(req.username) - 1);
    req.password_len = (uint32_t)pass_len;

    send_fd_with_request(sv[0], shm_fd, &req);

    struct auth_reply reply;
    ssize_t got = recv(sv[0], &reply, sizeof(reply), 0);
    if (got != (ssize_t)sizeof(reply)) {
        die("recv auth reply");
    }

    printf("Backend result: %s (%s)\n", reply.ok ? "ALLOW" : "DENY", reply.message);

    explicit_bzero_local(password, SHM_SIZE);
    munmap(password, SHM_SIZE);
    close(shm_fd);
    close(sv[0]);

    int status = 0;
    waitpid(child, &status, 0);
    printf("Backend process %ld exited with status %d\n", (long)child, status);
    return reply.ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
