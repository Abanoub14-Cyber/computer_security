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
        printf("[checksum] %s\n", label);
        save_success("archive.tar", (*sc)++);
    }
}


void fuzz_checksum(char *extractor, int *sc) {
    struct tar_t h;

    init_header(&h, "test.txt", '0', 0);
    run_case(extractor, sc, &h, "valid checksum (baseline)");

    // case 1 : invalid structure 

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '0', 8);                  
    run_case(extractor, sc, &h, "all ASCII '0'");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, ' ', 8);                 
    run_case(extractor, sc, &h, "all spaces");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '\0', 8);                 
    run_case(extractor, sc, &h, "all NUL bytes");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '\xFF', 8);               
    run_case(extractor, sc, &h, "all 0xFF");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '1', 8);                
    run_case(extractor, sc, &h, "no null terminator");

    // case 2 : no octal

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "FFFFFFFF", 8);           
    run_case(extractor, sc, &h, "non-octal hex letters");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "99999999", 8);          
    run_case(extractor, sc, &h, "non-octal digits 9");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "-000001 ", 8);           
    run_case(extractor, sc, &h, "negative value");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "77777777", 8);           
    run_case(extractor, sc, &h, "max octal value");

    // case 3 : off-by-n checksum

    init_header(&h, "test.txt", '0', 0);
    unsigned int chk = calculate_checksum(&h);

    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk + 1);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct + 1");

    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk - 1);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct - 1");

    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk + 1000);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct + 1000");

    // case 4 : no standard but valid formats

    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    snprintf(h.chksum, 7, "%06o", chk & 0x3FFFF);
    h.chksum[6] = ' '; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "valid value, two trailing spaces");

    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    snprintf(h.chksum, 7, "%06o", chk);
    h.chksum[6] = '\0'; h.chksum[7] = '\0';
    run_case(extractor, sc, &h, "valid value, two NUL terminators");

    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    snprintf(h.chksum, sizeof(h.chksum), "%6o", chk); 
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "valid value, leading spaces not zeros");

    // case 5 : Signed and unsigned sum confusion


    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\x80', 100);               
    memset(h.chksum, ' ', 8);
    unsigned int usum = 0;
    unsigned char *raw = (unsigned char *)&h;
    for (int i = 0; i < 512; i++) usum += raw[i];
    int ssum = (int)usum - 256 * 100;
    if (ssum > 0) {
        snprintf(h.chksum, 7, "%06o", (unsigned int)ssum & 0x3FFFF);
        h.chksum[6] = '\0'; h.chksum[7] = ' ';
    }
    run_case(extractor, sc, &h, "signed-sum interpretation stored");

    // case 6 : buggy extractor that doesn't blank chksum field before summing

    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);             
    unsigned int buggy_sum = 0;
    raw = (unsigned char *)&h;
    for (int i = 0; i < 512; i++) buggy_sum += raw[i];
    snprintf(h.chksum, 7, "%06o", buggy_sum);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "checksum computed without blanking chksum field");

    // case 7 : Multi-file archive: bad checksum only on second entry

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        init_header(&h1, "first.txt", '0', 5);
        write_tar(f, &h1, "hello", 5);

        init_header(&h2, "second.txt", '0', 0);
        memset(h2.chksum, '\xFF', 8);
        write_tar(f, &h2, NULL, 0);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[checksum] bad checksum on second entry only\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    // case 8 : Multi-file archive: bad checksum only on first entry

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        init_header(&h1, "first.txt", '0', 5);
        memset(h1.chksum, '0', 8);
        fwrite(&h1, 512, 1, f);
        char pad[512] = {0};
        memcpy(pad, "hello", 5);
        fwrite(pad, 512, 1, f);

        init_header(&h2, "second.txt", '0', 0);
        write_tar(f, &h2, NULL, 0);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[checksum] bad checksum on first entry only\n");
            save_success("archive.tar", (*sc)++);
        }
    }
}
