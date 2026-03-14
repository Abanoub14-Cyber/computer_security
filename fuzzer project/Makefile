CC     = gcc
CFLAGS = -std=c99 -Wall -Wextra -Isrc

SRCS = $(wildcard src/*.c)

all: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o fuzzer

clean:
	rm -f fuzzer archive.tar crashing success_*.tar
