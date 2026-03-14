#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/*
 * fuzz_typeflag  –  tests semantic edge-cases for the typeflag field.
 *
 * We do NOT iterate blindly over all 256 byte values: that would be
 * unsound (the assignment forbids it) and would miss the real bugs.
 * Instead we cover:
 *   • Every POSIX-defined type used in an unexpected but plausible way.
 *   • Boundary / rarely-handled values just outside the defined range.
 *   • Combinations of typeflag with contradictory other fields (size,
 *     linkname, trailing slash in name, …).
 */
void fuzz_typeflag(char *extractor, int *sc) {
    FILE *f;
    struct tar_t h;

    /* ── 1. Undefined / reserved single-byte values ─────────────────── */

    /* '8'..'9' : just above the last defined POSIX type ('7') */
    for (char c = '8'; c <= '9'; c++) {
        f = fopen("archive.tar", "wb");
        init_header(&h, "test.txt", c, 0);
        write_tar(f, &h, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[typeflag] undefined value '%c' (0x%02x)\n",
               c, (unsigned char)c);
            save_success("archive.tar", (*sc)++);
        }
    }

    /* 'A'..'Z' : upper-case letters are extension flags in some variants */
    for (char c = 'A'; c <= 'Z'; c++) {
        f = fopen("archive.tar", "wb");
        init_header(&h, "test.txt", c, 0);
        write_tar(f, &h, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[typeflag] upper-case letter '%c' (0x%02x)\n",
               c, (unsigned char)c);
            save_success("archive.tar", (*sc)++);
        }
    }

    /* Non-printable / high-byte values: \x80 and \xFF are commonly
       mistaken for valid flags by extractors that use signed char */
    unsigned char probes[] = { 0x01, 0x7F, 0x80, 0xFE, 0xFF };
    for (int i = 0; i < (int)(sizeof probes); i++) {
        f = fopen("archive.tar", "wb");
        init_header(&h, "test.txt", (char)probes[i], 0);
        write_tar(f, &h, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[typeflag] non-printable 0x%02x\n", probes[i]);
            save_success("archive.tar", (*sc)++);
        }
    }

    /* ── 2. Contradictory typeflag + size combinations ───────────────── */

    /* Directory ('5') but size > 0 */
    f = fopen("archive.tar", "wb");
    init_header(&h, "mydir/", '5', 4096);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] directory with size > 0\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Symlink ('2') with actual file data */
    f = fopen("archive.tar", "wb");
    init_header(&h, "link.txt", '2', 100);
    strncpy(h.linkname, "/etc/passwd", 100);
    calculate_checksum(&h);
    char data[100];
    memset(data, 'X', 100);
    write_tar(f, &h, data, 100);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] symlink with data payload\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Hard link ('1') with enormous declared size */
    f = fopen("archive.tar", "wb");
    init_header(&h, "hard.txt", '1', 0);
    memcpy(h.size, "77777777777\0", 12);
    strncpy(h.linkname, "target.txt", 100);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] hard link with huge size\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Regular file ('0') whose name ends with '/' — ambiguous */
    f = fopen("archive.tar", "wb");
    init_header(&h, "ambiguous/", '0', 0);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] regular file with trailing slash in name\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Null typeflag ('\0') with enormous size */
    f = fopen("archive.tar", "wb");
    init_header(&h, "test.txt", '\0', 0);
    memcpy(h.size, "77777777777\0", 12);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] null typeflag with huge size\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 3. Typeflag + data that looks like a nested header ──────────── */

    /* Directory ('5') with size=512 and a fake header as its "data" */
    f = fopen("archive.tar", "wb");
    init_header(&h, "mydir/", '5', 512);
    calculate_checksum(&h);
    struct tar_t fake;
    init_header(&fake, "hidden.txt", '0', 0);
    fwrite(&h, 512, 1, f);
    fwrite(&fake, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] directory with embedded header as data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 4. Rarely-handled but defined types ─────────────────────────── */

    /* FIFO ('6') with non-zero size */
    f = fopen("archive.tar", "wb");
    init_header(&h, "myfifo", '6', 512);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] FIFO with non-zero size\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Character device ('3') with data */
    f = fopen("archive.tar", "wb");
    init_header(&h, "mydev", '3', 1024);
    calculate_checksum(&h);
    char devdata[1024];
    memset(devdata, '\xDE', 1024);
    write_tar(f, &h, devdata, 1024);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] character device with data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Block device ('4') with data */
    f = fopen("archive.tar", "wb");
    init_header(&h, "myblk", '4', 512);
    calculate_checksum(&h);
    char blkdata[512];
    memset(blkdata, '\xBE', 512);
    write_tar(f, &h, blkdata, 512);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] block device with data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Contiguous file ('7') — reserved, rarely handled */
    f = fopen("archive.tar", "wb");
    init_header(&h, "contig.dat", '7', 10);
    write_tar(f, &h, "0123456789", 10);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] contiguous file ('7')\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 5. Self-referential / circular symlink ──────────────────────── */

    f = fopen("archive.tar", "wb");
    init_header(&h, "selflink", '2', 0);
    strncpy(h.linkname, "selflink", 100);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] self-referencing symlink\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 6. Regular file with negative size ──────────────────────────── */

    f = fopen("archive.tar", "wb");
    init_header(&h, "neg.txt", '0', 0);
    memcpy(h.size, "-0000000001", 12);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[typeflag] regular file with negative size\n");
        save_success("archive.tar", (*sc)++);
    }
}
