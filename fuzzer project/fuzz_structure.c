#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/* ── fuzz_structure ──────────────────────────────────────────────────── */

void fuzz_structure(char *extractor, int *sc) {
    FILE *f;
    struct tar_t h1, h2, h3;
    char zeros[512];
    memset(zeros, 0, 512);

    /* ── 1. End-of-archive marker variants ───────────────────────────── */

    /* Zero-byte file */
    f = fopen("archive.tar", "wb");
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] zero-byte file\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Only the two end-of-archive zero blocks, no entries */
    f = fopen("archive.tar", "wb");
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] empty archive (only end marker)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Only one zero block instead of two */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    write_tar(f, &h1, NULL, 0);
    fwrite(zeros, 512, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] incomplete end-of-archive (one zero block)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Three consecutive zero blocks */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    write_tar(f, &h1, NULL, 0);
    fwrite(zeros, 512, 1, f);
    fwrite(zeros, 512, 1, f);
    fwrite(zeros, 512, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] three consecutive zero blocks at end\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Many zero blocks (10) */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    write_tar(f, &h1, NULL, 0);
    for (int i = 0; i < 10; i++)
        fwrite(zeros, 512, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] ten consecutive zero blocks at end\n");
        save_success("archive.tar", (*sc)++);
    }

    /* End-of-archive marker in the middle, valid entry after it */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "before.txt", '0', 5);
    write_tar(f, &h1, "hello", 5);
    write_end(f);                           /* end marker here */
    init_header(&h2, "after.txt", '0', 5);  /* entry after end marker */
    write_tar(f, &h2, "world", 5);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] valid entry after end-of-archive marker\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 2. Truncated archives ───────────────────────────────────────── */

    /* Header truncated to 1 byte */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    fwrite(&h1, 1, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] header truncated to 1 byte\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Header truncated to exactly half (256 bytes) */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    fwrite(&h1, 256, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] header truncated to 256 bytes (half)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Header truncated to 511 bytes (one byte short) */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    fwrite(&h1, 511, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] header truncated to 511 bytes (one short)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Valid file then truncated second header (100 bytes) */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "first.txt", '0', 5);
    write_tar(f, &h1, "hello", 5);
    init_header(&h2, "second.txt", '0', 0);
    fwrite(&h2, 100, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] valid file then truncated second header\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Header with no end-of-archive at all */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    fwrite(&h1, 512, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] single header, no end-of-archive\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Declared size > actual data written */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 1000);
    write_tar(f, &h1, "hi", 2);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] declared size > actual data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Declared size > actual data, no end marker */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "trunc.txt", '0', 1024);
    fwrite(&h1, 512, 1, f);
    char partial[256];
    memset(partial, 'X', 256);
    fwrite(partial, 1, 256, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] truncated data block, no end marker\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 3. Size vs. data mismatches ─────────────────────────────────── */

    /* Declared size < actual data written */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 2);
    char bigdata[1000];
    memset(bigdata, 0, 1000);
    write_tar(f, &h1, bigdata, 1000);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] declared size < actual data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Two files, second declares huge size */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "file1.txt", '0', 5);
    write_tar(f, &h1, "hello", 5);
    init_header(&h2, "file2.txt", '0', 0);
    memcpy(h2.size, "77777777777\0", 12);
    calculate_checksum(&h2);
    write_tar(f, &h2, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] two files, second has huge declared size\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 4. Misaligned data blocks ───────────────────────────────────── */

    /*
     * Write a file entry but pad with only 1 byte instead of the correct
     * 507 bytes, so the next header starts at offset 513+5+1=519 (wrong).
     * The extractor reads garbage as a header.
     */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "file1.txt", '0', 5);
    fwrite(&h1, 512, 1, f);
    fwrite("hello", 5, 1, f);
    fwrite("\x00", 1, 1, f);              /* only 1 byte of padding */
    init_header(&h2, "file2.txt", '0', 0);
    fwrite(&h2, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] misaligned: 1-byte pad instead of 507\n");
        save_success("archive.tar", (*sc)++);
    }

    /*
     * No padding at all after data — next header immediately follows data.
     */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "file1.txt", '0', 5);
    fwrite(&h1, 512, 1, f);
    fwrite("hello", 5, 1, f);            /* no padding */
    init_header(&h2, "file2.txt", '0', 0);
    fwrite(&h2, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] misaligned: no padding after data\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 5. Corrupt / junk headers ───────────────────────────────────── */

    /* Header all 0xFF */
    f = fopen("archive.tar", "wb");
    memset(&h1, '\xFF', 512);
    fwrite(&h1, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] header all 0xFF\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Header all 0x00 (not treated as end marker — extra zero block before end) */
    f = fopen("archive.tar", "wb");
    memset(&h1, '\x00', 512);
    fwrite(&h1, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] header all zeros before end marker\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Deterministic garbage header */
    f = fopen("archive.tar", "wb");
    char garbage[512];
    for (int i = 0; i < 512; i++)
        garbage[i] = (char)(i * 37 + 13);
    fwrite(garbage, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] garbage header\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Valid entry then all-0xFF header */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "first.txt", '0', 0);
    write_tar(f, &h1, NULL, 0);
    memset(&h2, '\xFF', 512);
    fwrite(&h2, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] valid entry then all-0xFF header\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Single 512-byte block of 0x01 (almost-zero, not an end marker) */
    f = fopen("archive.tar", "wb");
    memset(&h1, '\x01', 512);
    fwrite(&h1, 512, 1, f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] single block all 0x01 (near-zero, not end marker)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 6. Interleaved valid and corrupt entries ────────────────────── */

    /* valid -> corrupt -> valid -> corrupt */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "good1.txt", '0', 0);
    write_tar(f, &h1, NULL, 0);
    memset(&h2, '\xFF', 512);
    fwrite(&h2, 512, 1, f);
    init_header(&h3, "good2.txt", '0', 0);
    write_tar(f, &h3, NULL, 0);
    memset(&h1, '\xFF', 512);
    fwrite(&h1, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] interleaved valid and corrupt entries\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 7. Size field causes next header to land inside data ─────────── */

    /*
     * file1 has size=0 but we write 512 bytes of data anyway and set
     * size=512 on file1.  Then file2's header begins right after file1's
     * data block — extractor must skip exactly one 512-byte data block
     * to find it.  We corrupt file2's size so it tries to seek into
     * file3's header bytes.
     */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "file1.txt", '0', 512);
    fwrite(&h1, 512, 1, f);
    char blk[512];
    memset(blk, 'A', 512);
    fwrite(blk, 512, 1, f);             /* one data block */
    init_header(&h2, "file2.txt", '0', 0);
    memcpy(h2.size, "77777777777\0", 12);
    calculate_checksum(&h2);
    fwrite(&h2, 512, 1, f);
    init_header(&h3, "file3.txt", '0', 0);
    write_tar(f, &h3, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] size causes seek into adjacent header\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 8. Bad checksum sequences ───────────────────────────────────── */

    /* Bad checksum on first entry, valid second */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "bad.txt", '0', 5);
    memcpy(h1.chksum, "00000000", 8);
    fwrite(&h1, 512, 1, f);
    char pad[512];
    memset(pad, 0, 512);
    memcpy(pad, "hello", 5);
    fwrite(pad, 512, 1, f);
    init_header(&h2, "good.txt", '0', 5);
    write_tar(f, &h2, "world", 5);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] bad checksum on first entry, valid second\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 9. Version / magic structural issues ────────────────────────── */

    /* Correct magic, wrong version */
    f = fopen("archive.tar", "wb");
    init_header(&h1, "test.txt", '0', 0);
    h1.version[0] = '\xFF';
    h1.version[1] = '\xFF';
    calculate_checksum(&h1);
    write_tar(f, &h1, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] correct magic, bad version bytes\n");
        save_success("archive.tar", (*sc)++);
    }

    /* ── 10. Multi-directory then huge-size file ─────────────────────── */

    f = fopen("archive.tar", "wb");
    init_header(&h1, "dir1/", '5', 0);
    write_tar(f, &h1, NULL, 0);
    init_header(&h1, "dir2/", '5', 0);
    write_tar(f, &h1, NULL, 0);
    init_header(&h2, "dir2/evil.txt", '0', 0);
    memcpy(h2.size, "77777777777\0", 12);
    calculate_checksum(&h2);
    write_tar(f, &h2, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[structure] dirs then file with huge declared size\n");
        save_success("archive.tar", (*sc)++);
    }
}

/* ── fuzz_many_files ─────────────────────────────────────────────────── */

void fuzz_many_files(char *extractor, int *sc) {
    FILE *f;
    struct tar_t h;
    char name[32];

    /* 1000 valid files in a row */
    f = fopen("archive.tar", "wb");
    for (int i = 0; i < 1000; i++) {
        snprintf(name, sizeof(name), "file_%04d.txt", i);
        init_header(&h, name, '0', 5);
        write_tar(f, &h, "hello", 5);
    }
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[many_files] 1000 valid files\n");
        save_success("archive.tar", (*sc)++);
    }

    /* 1000 zero-size files — stresses header parsing without data I/O */
    f = fopen("archive.tar", "wb");
    for (int i = 0; i < 1000; i++) {
        snprintf(name, sizeof(name), "empty_%04d.txt", i);
        init_header(&h, name, '0', 0);
        write_tar(f, &h, NULL, 0);
    }
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[many_files] 1000 zero-size files\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Mix of types: dirs, files, symlinks */
    f = fopen("archive.tar", "wb");
    for (int i = 0; i < 100; i++) {
        snprintf(name, sizeof(name), "dir_%03d/", i);
        init_header(&h, name, '5', 0);
        write_tar(f, &h, NULL, 0);

        snprintf(name, sizeof(name), "dir_%03d/file.txt", i);
        init_header(&h, name, '0', 3);
        write_tar(f, &h, "abc", 3);

        snprintf(name, sizeof(name), "link_%03d", i);
        init_header(&h, name, '2', 0);
        strncpy(h.linkname, "dir_000/file.txt", 100);
        calculate_checksum(&h);
        write_tar(f, &h, NULL, 0);
    }
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[many_files] mixed 300 entries (dirs, files, symlinks)\n");
        save_success("archive.tar", (*sc)++);
    }

    /* Many files followed by one with a corrupt header */
    f = fopen("archive.tar", "wb");
    for (int i = 0; i < 100; i++) {
        snprintf(name, sizeof(name), "file_%04d.txt", i);
        init_header(&h, name, '0', 0);
        write_tar(f, &h, NULL, 0);
    }
    struct tar_t hbad;
    memset(&hbad, '\xFF', 512);
    fwrite(&hbad, 512, 1, f);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[many_files] 100 valid files then corrupt header\n");
        save_success("archive.tar", (*sc)++);
    }
}