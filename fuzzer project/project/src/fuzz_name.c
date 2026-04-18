#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

static void run_case(char *extractor, int *sc,
                     struct tar_t *h, const char *label) {
    FILE *f = fopen("archive.tar", "wb");
    write_tar(f, h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[name] %s\n", label);
        save_success("archive.tar", (*sc)++);
    }
}

void fuzz_name(char *extractor, int *sc) {
    struct tar_t h;

    // 1. Boundary / termination 
    init_header(&h, "test.txt", '0', 0);
    memset(h.name, 'A', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "no null terminator (all 'A')");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\0', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "all NUL bytes (empty name)");

    init_header(&h, "test.txt", '0', 0);
    h.name[0] = '\0';
    memset(h.name + 1, 'A', 99);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "NUL at position 0, non-zero tail");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\xFF', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "all 0xFF no null");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, 'B', 99);
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "max length 99 chars + NUL at byte 99");

    // 2. Special single-entry names

    init_header(&h, ".", '0', 0);
    run_case(extractor, sc, &h, "single dot '.'");

    init_header(&h, "..", '0', 0);
    run_case(extractor, sc, &h, "double dot '..'");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, ' ', 99);
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "all spaces");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\t', 99);
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "all tab characters");

    init_header(&h, "test.txt", '0', 0);
    for (int i = 0; i < 99; i++)
        h.name[i] = (i % 2 == 0) ? ' ' : '\t';
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "alternating spaces and tabs");

    init_header(&h, "ambiguous/", '0', 0);
    run_case(extractor, sc, &h, "regular file with trailing slash");

    // 3. Path traversal via name

    init_header(&h, "../../etc/passwd", '0', 0);
    run_case(extractor, sc, &h, "path traversal ../../etc/passwd");

    init_header(&h, "/tmp/evil.txt", '0', 0);
    run_case(extractor, sc, &h, "absolute path /tmp/evil.txt");

    init_header(&h, "/", '0', 0);
    run_case(extractor, sc, &h, "absolute path root /");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\0', 100);
    for (int i = 0; i + 3 <= 99; i += 3)
        memcpy(h.name + i, "../", 3);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "maximum depth path traversal ../../../...");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '/', 99);
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "all slashes");

    init_header(&h, "test.txt", '0', 0);
    for (int i = 0; i < 98; i += 2) {
        h.name[i]   = 'a';
        h.name[i+1] = '/';
    }
    h.name[98] = 'x';
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "deeply nested a/a/a/.../x");

    // 4. Embedded null bytes

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.name, "file\0hidden\0.txt", 16);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "embedded NUL: file\\0hidden\\0.txt");

    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\0', 100);
    memcpy(h.name, "../../\0etc/passwd", 17);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "embedded NUL inside path traversal");

    // 5. prefix field attacks

    init_header(&h, "test.txt", '0', 0);
    memset(h.prefix, 'P', 154);
    h.prefix[154] = '\0';
    memset(h.name, 'N', 99);
    h.name[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: max prefix(154) + max name(99)");

    init_header(&h, "passwd", '0', 0);
    memset(h.prefix, '\0', 155);
    memcpy(h.prefix, "../../etc", 9);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: path traversal ../../etc + name passwd");

    init_header(&h, "evil.txt", '0', 0);
    memset(h.prefix, '\0', 155);
    memcpy(h.prefix, "/tmp", 4);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: absolute /tmp + name evil.txt");

    init_header(&h, "test.txt", '0', 0);
    memset(h.prefix, '\xFF', 155);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: all 0xFF no null");

    init_header(&h, "test.txt", '0', 0);
    memset(h.prefix, '/', 154);
    h.prefix[154] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: all slashes");

    init_header(&h, "test.txt", '0', 0);
    memset(h.prefix, '\0', 155);
    memcpy(h.prefix, "dir\0hidden", 10);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "prefix: embedded NUL dir\\0hidden");

    // 6. Multi-entry: duplicate and conflicting names
    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;
        init_header(&h1, "same.txt", '0', 5);
        write_tar(f, &h1, "hello", 5);
        init_header(&h2, "same.txt", '0', 5);
        write_tar(f, &h2, "world", 5);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[name] duplicate filename in archive\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;
        init_header(&h1, "conflict/", '5', 0);
        write_tar(f, &h1, NULL, 0);
        init_header(&h2, "conflict", '0', 0);
        write_tar(f, &h2, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[name] directory then file with same base name\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;
        init_header(&h1, "conflict", '0', 0);
        write_tar(f, &h1, NULL, 0);
        init_header(&h2, "conflict/", '5', 0);
        write_tar(f, &h2, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[name] file then directory with same base name\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;
        init_header(&h1, "item", '0', 0);
        write_tar(f, &h1, NULL, 0);
        init_header(&h2, "item/", '0', 0);
        write_tar(f, &h2, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[name] same name differing only by trailing slash\n");
            save_success("archive.tar", (*sc)++);
        }
    }
}