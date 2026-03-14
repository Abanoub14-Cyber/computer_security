#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/*
 * fuzz_uname_gname  –  tests the uname and gname string fields.
 *
 * uname is at offset 265, gname at offset 297, each 32 bytes wide.
 * gname is immediately followed by devmajor, uname by gname —
 * an unterminated read bleeds into the next field.
 */

/* ── helper ──────────────────────────────────────────────────────────── */

static void run_case(char *extractor, int *sc,
                     struct tar_t *h, const char *label) {
    FILE *f = fopen("archive.tar", "wb");
    write_tar(f, h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[uname_gname] %s\n", label);
        save_success("archive.tar", (*sc)++);
    }
}

/* Apply the same pattern to uname then gname independently */
static void per_field(char *extractor, int *sc,
                      void (*mutate)(struct tar_t *, int /*field: 0=uname,1=gname*/),
                      const char *label) {
    char buf[64];
    struct tar_t h;

    /* uname only */
    init_header(&h, "test.txt", '0', 0);
    mutate(&h, 0);
    calculate_checksum(&h);
    snprintf(buf, sizeof(buf), "uname: %s", label);
    run_case(extractor, sc, &h, buf);

    /* gname only */
    init_header(&h, "test.txt", '0', 0);
    mutate(&h, 1);
    calculate_checksum(&h);
    snprintf(buf, sizeof(buf), "gname: %s", label);
    run_case(extractor, sc, &h, buf);
}

/* ── mutators ─────────────────────────────────────────────────────────── */

static char *field_ptr(struct tar_t *h, int field) {
    return field == 0 ? h->uname : h->gname;
}

static void mut_no_null_A(struct tar_t *h, int f) {
    memset(field_ptr(h, f), 'A', 32);
}
static void mut_no_null_ff(struct tar_t *h, int f) {
    memset(field_ptr(h, f), '\xFF', 32);
}
static void mut_all_zero(struct tar_t *h, int f) {
    memset(field_ptr(h, f), '\0', 32);
}
static void mut_max_len(struct tar_t *h, int f) {
    /* 31 chars + NUL at byte 31 — maximum valid length */
    memset(field_ptr(h, f), 'Z', 31);
    field_ptr(h, f)[31] = '\0';
}
static void mut_null_at_0(struct tar_t *h, int f) {
    /* NUL at byte 0, rest non-zero — strlen sees empty, field is not */
    memset(field_ptr(h, f), 'C', 32);
    field_ptr(h, f)[0] = '\0';
}
static void mut_embedded_null(struct tar_t *h, int f) {
    /* "root\0AAAAA..." — strlen sees "root", raw field has more */
    memset(field_ptr(h, f), 'A', 32);
    memcpy(field_ptr(h, f), "root\0PADDING", 12);
}
static void mut_all_spaces(struct tar_t *h, int f) {
    memset(field_ptr(h, f), ' ', 32);
}
static void mut_all_tabs(struct tar_t *h, int f) {
    memset(field_ptr(h, f), '\t', 32);
}
static void mut_control_bytes(struct tar_t *h, int f) {
    /* \x01..\x1F cycling through control characters */
    char *p = field_ptr(h, f);
    for (int i = 0; i < 32; i++)
        p[i] = (char)(1 + (i % 31));
}

/* ── public entry point ──────────────────────────────────────────────── */

void fuzz_uname_gname(char *extractor, int *sc) {
    struct tar_t h;

    /* ── 1. Per-field cases (uname alone, then gname alone) ──────────── */

    per_field(extractor, sc, mut_no_null_A,      "32 bytes no null terminator");
    per_field(extractor, sc, mut_no_null_ff,     "32 0xFF bytes, no null");
    per_field(extractor, sc, mut_all_zero,       "all zeros (empty string)");
    per_field(extractor, sc, mut_max_len,        "max length: 31 chars + NUL at byte 31");
    per_field(extractor, sc, mut_null_at_0,      "NUL at byte 0, rest non-zero");
    per_field(extractor, sc, mut_embedded_null,  "embedded NUL: 'root\\0AAAA...'");
    per_field(extractor, sc, mut_all_spaces,     "all spaces");
    per_field(extractor, sc, mut_all_tabs,       "all tab characters");
    per_field(extractor, sc, mut_control_bytes,  "control characters 0x01-0x1F");

    /* ── 2. Both fields corrupted simultaneously ─────────────────────── */

    /* Both no-null: uname bleeds into gname, gname bleeds into devmajor */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, 'A', 32);
    memset(h.gname, 'B', 32);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "both: uname 'A'x32 + gname 'B'x32, no nulls");

    /* Both all 0xFF */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, '\xFF', 32);
    memset(h.gname, '\xFF', 32);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "both: all 0xFF, no nulls");

    /* Both all spaces */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, ' ', 32);
    memset(h.gname, ' ', 32);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "both: all spaces");

    /* uname no-null, gname all-zero */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, 'A', 32);
    memset(h.gname, '\0', 32);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "both: uname no-null + gname all-zero");

    /* uname all-zero, gname no-null */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, '\0', 32);
    memset(h.gname, 'B', 32);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "both: uname all-zero + gname no-null");

    /* ── 3. uname/gname vs uid/gid mismatch ──────────────────────────── */

    /* uname = "root" (uid 0) but uid field = 9999 */
    init_header(&h, "test.txt", '0', 0);
    strncpy(h.uname, "root", 32);
    memcpy(h.uid, "0017537\0", 8);  /* 9999 in octal */
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "uname='root' but uid=9999 (mismatch)");

    /* gname = "root" but gid = 9999 */
    init_header(&h, "test.txt", '0', 0);
    strncpy(h.gname, "root", 32);
    memcpy(h.gid, "0017537\0", 8);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "gname='root' but gid=9999 (mismatch)");

    /* uname = valid system name, uid = 0 (root uid, non-root name) */
    init_header(&h, "test.txt", '0', 0);
    strncpy(h.uname, "nobody", 32);
    memcpy(h.uid, "0000000\0", 8);  /* uid 0 = root */
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "uname='nobody' but uid=0 (root uid)");

    /* uname no-null + mismatched uid */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname, 'A', 32);      /* no null */
    memcpy(h.uid, "0017537\0", 8);
    calculate_checksum(&h);
    run_case(extractor, sc, &h, "uname no-null + uid=9999");

    /* ── 4. Field bleed into adjacent fields ─────────────────────────── */

    /* uname fills bytes 265-296, gname fills 297-328, devmajor at 329.
       Write 32 non-null bytes in uname so any strcpy into a 32-byte
       buffer overflows by one into gname. */
    init_header(&h, "test.txt", '0', 0);
    memset(h.uname,    'U', 32);   /* no NUL — bleeds into gname */
    memset(h.gname,    'G', 32);   /* no NUL — bleeds into devmajor */
    memset(h.devmajor, 'D',  8);   /* corrupt devmajor too */
    calculate_checksum(&h);
    run_case(extractor, sc, &h,
             "uname+gname+devmajor all no-null: cross-field bleed");
}