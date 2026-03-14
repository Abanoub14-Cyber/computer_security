#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/* ── helpers ─────────────────────────────────────────────────────────── */

/*
 * Write a single-entry archive with the given raw chksum bytes and run
 * the extractor.  The caller is responsible for filling h->chksum before
 * calling this.
 */
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

/* ── public entry point ──────────────────────────────────────────────── */

void fuzz_checksum(char *extractor, int *sc) {
    struct tar_t h;

    /* ── 0. Baseline: correct checksum (happy path) ──────────────────── */
    init_header(&h, "test.txt", '0', 0);
    /* calculate_checksum already called by init_header — just run it */
    run_case(extractor, sc, &h, "valid checksum (baseline)");

    /* ── 1. Structurally invalid byte patterns ───────────────────────── */

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '0', 8);                  /* "00000000" — parseable zero */
    run_case(extractor, sc, &h, "all ASCII '0'");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, ' ', 8);                  /* all spaces */
    run_case(extractor, sc, &h, "all spaces");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '\0', 8);                 /* all NUL bytes */
    run_case(extractor, sc, &h, "all NUL bytes");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '\xFF', 8);               /* all 0xFF */
    run_case(extractor, sc, &h, "all 0xFF");

    init_header(&h, "test.txt", '0', 0);
    memset(h.chksum, '1', 8);                  /* 8 digits, no NUL terminator */
    run_case(extractor, sc, &h, "no null terminator");

    /* ── 2. Non-octal / non-numeric content ─────────────────────────── */

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "FFFFFFFF", 8);           /* hex letters */
    run_case(extractor, sc, &h, "non-octal hex letters");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "99999999", 8);           /* digits 8-9 invalid in octal */
    run_case(extractor, sc, &h, "non-octal digits 9");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "-000001 ", 8);           /* negative value */
    run_case(extractor, sc, &h, "negative value");

    init_header(&h, "test.txt", '0', 0);
    memcpy(h.chksum, "77777777", 8);           /* max 8-digit octal, no NUL */
    run_case(extractor, sc, &h, "max octal value");

    /* ── 3. Off-by-N on a correct checksum ──────────────────────────── */

    init_header(&h, "test.txt", '0', 0);
    unsigned int chk = calculate_checksum(&h);

    /* +1 */
    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk + 1);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct + 1");

    /* -1 */
    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk - 1);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct - 1");

    /* wildly wrong: +1000 */
    init_header(&h, "test.txt", '0', 0);
    snprintf(h.chksum, sizeof(h.chksum), "%06o", chk + 1000);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "correct + 1000");

    /* ── 4. Valid value, non-standard formatting ─────────────────────── */

    /* "OOOOOO  " — two trailing spaces instead of the standard \0+space */
    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    /* write value then force two trailing spaces manually */
    snprintf(h.chksum, 7, "%06o", chk & 0x3FFFF);
    h.chksum[6] = ' '; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "valid value, two trailing spaces");

    /* "OOOOOO\0\0" — two NULs instead of \0+space */
    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    snprintf(h.chksum, 7, "%06o", chk);
    h.chksum[6] = '\0'; h.chksum[7] = '\0';
    run_case(extractor, sc, &h, "valid value, two NUL terminators");

    /* Leading spaces instead of leading zeros: "  1234\0 " */
    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);
    snprintf(h.chksum, sizeof(h.chksum), "%6o", chk); /* %6o uses spaces */
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "valid value, leading spaces not zeros");

    /* ── 5. Signed vs. unsigned sum confusion ────────────────────────── */

    /*
     * If an extractor computes the checksum with `signed char` instead of
     * `unsigned char`, bytes >= 0x80 contribute negative amounts.
     * Build a header whose bytes make the signed sum equal the stored value
     * but the unsigned sum differ — or vice versa.
     *
     * Strategy: fill name with 0x80 bytes.  Each 0x80 byte contributes
     * +128 unsigned but -128 signed, a difference of 256 per byte.
     * With N such bytes, signed_sum = unsigned_sum - 256*N.
     * Store the signed interpretation as the checksum.
     */
    init_header(&h, "test.txt", '0', 0);
    memset(h.name, '\x80', 100);               /* 100 bytes of 0x80 */
    /* compute unsigned sum manually */
    memset(h.chksum, ' ', 8);
    unsigned int usum = 0;
    unsigned char *raw = (unsigned char *)&h;
    for (int i = 0; i < 512; i++) usum += raw[i];
    /* signed sum = usum - 256*100 */
    int ssum = (int)usum - 256 * 100;
    if (ssum > 0) {
        snprintf(h.chksum, 7, "%06o", (unsigned int)ssum & 0x3FFFF);
        h.chksum[6] = '\0'; h.chksum[7] = ' ';
    }
    run_case(extractor, sc, &h, "signed-sum interpretation stored");

    /* ── 6. chksum field not blanked before re-summing ───────────────── */

    /*
     * Some extractors forget to replace chksum with spaces before
     * recomputing the sum to verify it.  They end up with a larger sum.
     * Store a value that equals that "wrong" sum so a buggy extractor
     * accepts it while a correct one rejects it — or crash either way.
     *
     * "Wrong" sum = correct_sum - sum_of_spaces(8*32) + sum_of_chksum_bytes
     */
    init_header(&h, "test.txt", '0', 0);
    chk = calculate_checksum(&h);              /* correct sum, chksum filled */
    /* Now compute what a buggy extractor would sum (not blanking chksum) */
    unsigned int buggy_sum = 0;
    raw = (unsigned char *)&h;
    for (int i = 0; i < 512; i++) buggy_sum += raw[i];
    /* Store the buggy sum so a buggy extractor thinks it's valid */
    snprintf(h.chksum, 7, "%06o", buggy_sum);
    h.chksum[6] = '\0'; h.chksum[7] = ' ';
    run_case(extractor, sc, &h, "checksum computed without blanking chksum field");

    /* ── 7. Multi-file archive: bad checksum only on second entry ─────── */

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        /* First entry: valid */
        init_header(&h1, "first.txt", '0', 5);
        write_tar(f, &h1, "hello", 5);

        /* Second entry: corrupt checksum */
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

    /* ── 8. Multi-file archive: bad checksum only on first entry ─────── */

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h1, h2;

        /* First entry: corrupt checksum */
        init_header(&h1, "first.txt", '0', 5);
        memset(h1.chksum, '0', 8);
        fwrite(&h1, 512, 1, f);
        char pad[512] = {0};
        memcpy(pad, "hello", 5);
        fwrite(pad, 512, 1, f);

        /* Second entry: valid */
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
