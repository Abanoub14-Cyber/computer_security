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
        printf("[magic] %s\n", label);
        save_success("archive.tar", (*sc)++);
    }
}

void fuzz_magic(char *extractor, int *sc) {
    struct tar_t h;

    init_header(&h, "test.txt", '0', 0);
    run_case(extractor, sc, &h, "valid magic + valid version (baseline)");

    struct { char bytes[6]; const char *label; } magics[] = {
        // almost correct 
        {{'U','S','T','A','R','\0'}, "uppercase USTAR\\0"},
        {{'u','s','t','a','r',' '}, "GNU magic: ustar<space>"},
        {{'u','s','t','a','x','\0'}, "one wrong letter at end: ustar->ustax"},
        {{'X','u','s','t','a','r'}, "wrong first byte"},
        {{'u','X','t','a','r','\0'}, "wrong second byte"},
        {{'u','s','X','a','r','\0'}, "wrong middle byte"},
        // ustar without NUL terminator 
        {{'u','s','t','a','r','!'}, "ustar + '!' instead of NUL"},
        {{'u','s','t','a','r','r'}, "ustar + extra 'r' instead of NUL"},
        // Truncated 
        {{'u','s','t','\0','\0','\0'}, "truncated: only 'ust'"},
        {{'u','\0','\0','\0','\0','\0'}, "truncated: only 'u'"},
        // wrong 
        {{'X','X','X','X','X','X'}, "all 'X', no NUL"},
        {{'\xFF','\xFF','\xFF','\xFF','\xFF','\xFF'}, "all 0xFF"},
        {{'\0','\0','\0','\0','\0','\0'}, "all NUL (old-format hint)"},
        {{' ',' ',' ',' ',' ',' '}, "all spaces"},
        {{'1','2','3','4','5','6'}, "digits 1-6"},
        {{'\x01','\x02','\x03','\x04','\x05','\x06'}, "control bytes 0x01-0x06"},
        {{'\xFF','\x00','\xFF','\x00','\xFF','\x00'}, "alternating 0xFF/0x00"},
        // Single-bit flip on correct bytes
        {{'u'^1,'s','t','a','r','\0'}, "single-bit flip on 'u'"},
        {{'u','s','t','a','r','\x01'}, "single-bit flip on NUL terminator"},
    };

    int nm = (int)(sizeof magics / sizeof magics[0]);
    for (int i = 0; i < nm; i++) {
        init_header(&h, "test.txt", '0', 0);
        memcpy(h.magic, magics[i].bytes, 6);
        calculate_checksum(&h);
        run_case(extractor, sc, &h, magics[i].label);
    }

    {
        char ver[3];
        char label[64];
        for (int v = 1; v <= 99; v++) {
            init_header(&h, "test.txt", '0', 0);
            snprintf(ver,   sizeof(ver),   "%02d", v);
            snprintf(label, sizeof(label), "version: \"%02d\" (decimal %d)", v, v);
            h.version[0] = ver[0];
            h.version[1] = ver[1];
            calculate_checksum(&h);
            run_case(extractor, sc, &h, label);
        }
    }

    struct { char bytes[2]; const char *label; } versions[] = {
        {{' ', '\0'}, "GNU version: <space>NUL"},
        {{' ', ' '},  "version: two spaces"},
        {{'\xFF', '\xFF'}, "version: 0xFF 0xFF"},
        {{'\0', '\0'}, "version: two NULs"},
        {{'\x01', '\x02'}, "version: control bytes 0x01 0x02"},
        {{'0', '\0'}, "version: '0' + NUL (only one digit)"},
    };

    int nv = (int)(sizeof versions / sizeof versions[0]);
    for (int i = 0; i < nv; i++) {
        init_header(&h, "test.txt", '0', 0);
        h.version[0] = versions[i].bytes[0];
        h.version[1] = versions[i].bytes[1];
        calculate_checksum(&h);
        run_case(extractor, sc, &h, versions[i].label);
    }

    init_header(&h, "test.txt", '0', 0);
    h.version[0] = '\xFF'; h.version[1] = '\xFF';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "good magic + bad version 0xFF 0xFF");

    init_header(&h, "test.txt", '0', 0);
    memset(h.magic, '\xFF', 6);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "bad magic 0xFF + good version 00");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.magic,   "ustar ", 6);
    h.version[0] = ' '; h.version[1] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "GNU format: magic 'ustar ' + version ' \\0'");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.magic, "ustar ", 6);
    h.version[0] = '0'; h.version[1] = '0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "GNU magic 'ustar ' + POSIX version '00'");

    init_header(&h, "test.txt", '0', 0);
    h.version[0] = ' '; h.version[1] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "POSIX magic 'ustar\\0' + GNU version ' \\0'");

    init_header(&h, "test.txt", '0', 0);
    h.version[0] = '\xFF'; h.version[1] = '\xFF';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "valid magic, garbage version: bleed test");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.magic, "ustar!!", 6);   
    h.version[0] = '0'; h.version[1] = '0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "magic without NUL bleeds into version field");

    init_header(&h, "test.txt", '0', 0);
    memset(h.magic,   ' ', 6);
    memset(h.version, ' ', 2);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "old format: magic all spaces, version all spaces");

    init_header(&h, "test.txt", '0', 0);
    memset(h.magic,   '\0', 6);
    memset(h.version, '\0', 2);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "old format: magic all NUL, version all NUL");

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        init_header(&h1, "first.txt", '0', 5);
        write_tar(f, &h1, "hello", 5);

        init_header(&h2, "second.txt", '0', 0);
        memset(h2.magic, '\xFF', 6);
        calculate_checksum(&h2);
        write_tar(f, &h2, NULL, 0);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[magic] multi-entry: valid first, bad magic on second\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        init_header(&h1, "first.txt", '0', 0);
        memset(h1.magic, '\xFF', 6);
        calculate_checksum(&h1);
        write_tar(f, &h1, NULL, 0);

        init_header(&h2, "second.txt", '0', 0);
        write_tar(f, &h2, NULL, 0);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[magic] multi-entry: bad magic on first, valid second\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.size, "77777777777\0", 12);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "valid magic + huge size, no data");
}