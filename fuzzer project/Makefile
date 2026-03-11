CC     = gcc
CFLAGS = -std=c99 -Wall -Wextra

SRCS = main.c help.c tar_utils.c extractor.c \
       fuzz_typeflag.c fuzz_name.c \
       fuzz_checksum.c fuzz_magic.c fuzz_structure.c \
       fuzz_numeric_fields.c fuzz_linkname.c \
       fuzz_uname_gname.c

all: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o fuzzer

clean:
	rm -f fuzzer archive.tar crashing success_*.tar
