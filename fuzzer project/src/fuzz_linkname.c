#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/* ── helper ──────────────────────────────────────────────────────────── */

static void run_case(char *extractor, int *sc,
                     struct tar_t *h, const char *label) {
    FILE *f = fopen("archive.tar", "wb");
    write_tar(f, h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[linkname] %s\n", label);
        save_success("archive.tar", (*sc)++);
    }
}

/* ── public entry point ──────────────────────────────────────────────── */

void fuzz_linkname(char *extractor, int *sc) {
    struct tar_t h;

    /* ── 1. No null terminator ───────────────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, 'A', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: no null terminator");

    init_header(&h, "hard.txt", '1', 0);
    memset(h.linkname, 'B', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "hardlink: no null terminator");

    init_header(&h, "test.txt", '0', 0);
    memset(h.linkname, 'A', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "regular file: non-empty linkname no null");

    /* ── 2. Extreme byte values ──────────────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, '\xFF', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: all 0xFF no null");

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, '\0', 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: empty linkname (all NUL)");

    /* ── 3. Maximum valid length (99 chars + NUL at byte 99) ─────────── */

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, 'C', 99);
    h.linkname[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: max length 99 chars + NUL");

    init_header(&h, "hard.txt", '1', 0);
    memset(h.linkname, 'C', 99);
    h.linkname[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "hardlink: max length 99 chars + NUL");

    /* ── 4. Path traversal in link target ────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    strncpy(h.linkname, "../../etc/passwd", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: path traversal ../../etc/passwd");

    init_header(&h, "link.txt", '2', 0);
    /* fill with as many ../ as fit */
    memset(h.linkname, 0, 100);
    const char *seg = "../";
    for (int i = 0; i + 3 <= 99; i += 3)
        memcpy(h.linkname + i, seg, 3);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: maximum depth path traversal");

    /* ── 5. Absolute path as link target ─────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    strncpy(h.linkname, "/etc/passwd", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: absolute path /etc/passwd");

    init_header(&h, "link.txt", '2', 0);
    strncpy(h.linkname, "/", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: absolute path root /");

    /* ── 6. linkname filled with slashes ─────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, '/', 99);
    h.linkname[99] = '\0';
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: all slashes");

    /* ── 7. Embedded null bytes ──────────────────────────────────────── */

    init_header(&h, "link.txt", '2', 0);
    memset(h.linkname, '\0', 100);
    memcpy(h.linkname, "target\0hidden", 13);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: embedded null byte in linkname");

    /* ── 8. Self-referencing symlink (name == linkname) ──────────────── */

    init_header(&h, "selflink", '2', 0);
    strncpy(h.linkname, "selflink", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "symlink: self-referencing (name == linkname)");

    /* ── 9. Hardlink target not present in archive ───────────────────── */

    init_header(&h, "hard.txt", '1', 0);
    strncpy(h.linkname, "nonexistent_target.txt", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "hardlink: target not in archive");

    /* ── 10. Valid-looking linkname on regular file ──────────────────── */

    init_header(&h, "test.txt", '0', 0);
    strncpy(h.linkname, "some_target.txt", 100);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "regular file: valid-looking linkname (should be ignored)");

    /* ── 11. Chained symlinks A → B → A (circular) ───────────────────── */

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t ha, hb;

        init_header(&ha, "linkA", '2', 0);
        strncpy(ha.linkname, "linkB", 100);
        calculate_checksum(&ha);
        write_tar(f, &ha, NULL, 0);

        init_header(&hb, "linkB", '2', 0);
        strncpy(hb.linkname, "linkA", 100);
        calculate_checksum(&hb);
        write_tar(f, &hb, NULL, 0);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[linkname] chained symlinks A->B->A (circular)\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    /* ── 12. Hardlink declared before its target exists in archive ───── */

    {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t hlink, htarget;

        /* hardlink comes first, target comes second */
        init_header(&hlink, "hard.txt", '1', 0);
        strncpy(hlink.linkname, "original.txt", 100);
        calculate_checksum(&hlink);
        write_tar(f, &hlink, NULL, 0);

        init_header(&htarget, "original.txt", '0', 5);
        write_tar(f, &htarget, "hello", 5);

        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[linkname] hardlink declared before target in archive\n");
            save_success("archive.tar", (*sc)++);
        }
    }
}