CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O2 -D_DEFAULT_SOURCE
LDFLAGS ?=

.PHONY: all clean test

all: Frontend Backend Sandbox test_binaries/quick_exit test_binaries/sleeper test_binaries/cpu_hog test_binaries/memory_hog

Frontend: Frontend.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lrt

Backend: Backend.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lrt

Sandbox: Sandbox.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -pthread

test_binaries/quick_exit: test_binaries/quick_exit.c
	$(CC) $(CFLAGS) -o $@ $<

test_binaries/sleeper: test_binaries/sleeper.c
	$(CC) $(CFLAGS) -o $@ $<

test_binaries/cpu_hog: test_binaries/cpu_hog.c
	$(CC) $(CFLAGS) -o $@ $<

test_binaries/memory_hog: test_binaries/memory_hog.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	./Frontend alice wonderland
	-./Frontend 'bad/user' wonderland
	-./Frontend alice wrong-password
	rm -f sandbox.log
	./Sandbox ./test_binaries/quick_exit
	-SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/sleeper
	-SANDBOX_TIME_LIMIT=2 ./Sandbox ./test_binaries/cpu_hog
	-SANDBOX_RSS_LIMIT_KB=12000 ./Sandbox ./test_binaries/memory_hog
	cat sandbox.log

clean:
	rm -f Frontend Backend Sandbox sandbox.log
	rm -f test_binaries/quick_exit test_binaries/sleeper test_binaries/cpu_hog test_binaries/memory_hog
