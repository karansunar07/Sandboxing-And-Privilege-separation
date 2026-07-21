#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIME_LIMIT 5
#define DEFAULT_RSS_LIMIT_KB 32768
#define POLL_MS 200

struct sandbox_state {
    pthread_mutex_t lock;
    pid_t child;
    int finished;
    int killed;
    int exit_status;
    int time_limit;
    long rss_limit_kb;
    struct timespec start;
    FILE *log;
};

static void log_line(struct sandbox_state *st, const char *fmt, ...) {
    pthread_mutex_lock(&st->lock);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(st->log, fmt, ap);
    fprintf(st->log, "\n");
    fflush(st->log);
    va_end(ap);
    pthread_mutex_unlock(&st->lock);
}

static double elapsed_seconds(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) +
           (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}

static long read_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        long value = -1;
        if (sscanf(line, "VmRSS: %ld kB", &value) == 1) {
            fclose(fp);
            return value;
        }
    }
    fclose(fp);
    return -1;
}

static int is_finished(struct sandbox_state *st) {
    int finished;
    pthread_mutex_lock(&st->lock);
    finished = st->finished;
    pthread_mutex_unlock(&st->lock);
    return finished;
}

static void mark_killed(struct sandbox_state *st) {
    pthread_mutex_lock(&st->lock);
    st->killed = 1;
    pthread_mutex_unlock(&st->lock);
}

static void terminate_child(struct sandbox_state *st, int sig, const char *reason) {
    pid_t group = -st->child;

    if (kill(group, 0) == -1 && errno == ESRCH) {
        return;
    }
    log_line(st, "policy: sending signal %d to process_group=%ld reason=%s",
             sig, (long)st->child, reason);
    if (kill(group, sig) == -1 && errno == ESRCH) {
        kill(st->child, sig);
    }
    mark_killed(st);
}

static void cleanup_process_group(struct sandbox_state *st) {
    pid_t group = -st->child;

    if (kill(group, 0) == -1 && errno == ESRCH) {
        return;
    }

    log_line(st, "policy: cleaning up remaining process_group=%ld with SIGKILL",
             (long)st->child);
    kill(group, SIGKILL);
    mark_killed(st);
}

static void *time_monitor(void *arg) {
    struct sandbox_state *st = arg;
    while (!is_finished(st)) {
        double elapsed = elapsed_seconds(&st->start);
        if (elapsed > st->time_limit) {
            terminate_child(st, SIGTERM, "time limit exceeded");
            usleep(500 * 1000);
            if (!is_finished(st)) {
                terminate_child(st, SIGKILL, "child ignored SIGTERM");
            }
            return NULL;
        }
        usleep(POLL_MS * 1000);
    }
    return NULL;
}

static void *resource_monitor(void *arg) {
    struct sandbox_state *st = arg;
    while (!is_finished(st)) {
        long rss = read_rss_kb(st->child);
        if (rss >= 0) {
            log_line(st, "monitor: pid=%ld rss_kb=%ld elapsed=%.2f",
                     (long)st->child, rss, elapsed_seconds(&st->start));
            if (rss > st->rss_limit_kb) {
                terminate_child(st, SIGKILL, "rss limit exceeded");
                return NULL;
            }
        }
        usleep(POLL_MS * 1000);
    }
    return NULL;
}

static void set_child_limits(void) {
    struct rlimit cpu = { 10, 10 };
    struct rlimit as = { 128 * 1024 * 1024, 128 * 1024 * 1024 };
    setrlimit(RLIMIT_CPU, &cpu);
    setrlimit(RLIMIT_AS, &as);
}

static int parse_positive_int_env(const char *name, int fallback) {
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (*end != '\0' || parsed <= 0 || parsed > 86400) {
        fprintf(stderr, "invalid %s, using default %d\n", name, fallback);
        return fallback;
    }
    return (int)parsed;
}

static long parse_positive_long_env(const char *name, long fallback) {
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (*end != '\0' || parsed <= 0) {
        fprintf(stderr, "invalid %s, using default %ld\n", name, fallback);
        return fallback;
    }
    return parsed;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <unsafe-binary> [args...]\n", argv[0]);
        fprintf(stderr, "environment: SANDBOX_TIME_LIMIT=5 SANDBOX_RSS_LIMIT_KB=32768\n");
        return EXIT_FAILURE;
    }

    struct sandbox_state st;
    memset(&st, 0, sizeof(st));
    pthread_mutex_init(&st.lock, NULL);
    st.time_limit = parse_positive_int_env("SANDBOX_TIME_LIMIT", DEFAULT_TIME_LIMIT);
    st.rss_limit_kb = parse_positive_long_env("SANDBOX_RSS_LIMIT_KB", DEFAULT_RSS_LIMIT_KB);
    st.log = fopen("sandbox.log", "a");
    if (st.log == NULL) {
        perror("sandbox.log");
        return EXIT_FAILURE;
    }
    clock_gettime(CLOCK_MONOTONIC, &st.start);

    st.child = fork();
    if (st.child == -1) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (st.child == 0) {
        if (setpgid(0, 0) == -1) {
            perror("setpgid child");
            _exit(126);
        }
        set_child_limits();
        char **child_argv = &argv[1];
        char *child_envp[] = { "PATH=/usr/bin:/bin", "MALLOC_ARENA_MAX=1", NULL };
        execve(child_argv[0], child_argv, child_envp);
        perror("execve unsafe binary");
        _exit(127);
    }

    if (setpgid(st.child, st.child) == -1 && errno != EACCES) {
        perror("setpgid parent");
    }

    log_line(&st, "sandbox: child pid=%ld exec=%s time_limit=%d rss_limit_kb=%ld",
             (long)st.child, argv[1], st.time_limit, st.rss_limit_kb);

    pthread_t time_thread, resource_thread;
    pthread_create(&time_thread, NULL, time_monitor, &st);
    pthread_create(&resource_thread, NULL, resource_monitor, &st);

    int status = 0;
    waitpid(st.child, &status, 0);

    pthread_mutex_lock(&st.lock);
    st.finished = 1;
    st.exit_status = status;
    pthread_mutex_unlock(&st.lock);

    cleanup_process_group(&st);

    pthread_join(time_thread, NULL);
    pthread_join(resource_thread, NULL);

    if (WIFSIGNALED(status)) {
        log_line(&st, "sandbox: child terminated by signal=%d", WTERMSIG(status));
    } else if (WIFEXITED(status)) {
        log_line(&st, "sandbox: child exited code=%d", WEXITSTATUS(status));
    }
    log_line(&st, "sandbox: killed_by_policy=%s", st.killed ? "yes" : "no");

    fclose(st.log);
    pthread_mutex_destroy(&st.lock);
    return st.killed ? EXIT_FAILURE : EXIT_SUCCESS;
}
