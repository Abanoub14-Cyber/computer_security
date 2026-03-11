#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "help.h"
#include "tar_utils.h"
#include "extractor.h"
#include "fuzz_cases.h"

/*
 * fuzz_numeric_fields  –  covers the octal-ASCII numeric header fields:
 *   size, mtime, uid, gid, mode.
 *
 * (devmajor, devminor, prefix, and padding are excluded per spec.)
 *
 * All five fields share the same set of invalid / boundary values.
 * A single helper avoids copy-paste: it receives a field descriptor and
 * iterates over the shared VECTORS table, clamping each vector to the
 * field's actual width so we never overrun a field.
 */

/* ── setter callbacks ──────────────────────────────────────────────── */

static void set_size (struct tar_t *h, const char *v, size_t n) { memcpy(h->size,  v, n); }
static void set_mtime(struct tar_t *h, const char *v, size_t n) { memcpy(h->mtime, v, n); }
static void set_uid  (struct tar_t *h, const char *v, size_t n) { memcpy(h->uid,   v, n); }
static void set_gid  (struct tar_t *h, const char *v, size_t n) { memcpy(h->gid,   v, n); }
static void set_mode (struct tar_t *h, const char *v, size_t n) { memcpy(h->mode,  v, n); }

typedef void (*setter_fn)(struct tar_t *, const char *, size_t);

typedef struct {
    const char *label;   /* human-readable field name   */
    setter_fn   set;     /* callback to mutate the field */
    int         width;   /* field width in bytes         */
} field_desc;

/* ── shared test vectors ───────────────────────────────────────────── */

typedef struct { const char *value; size_t len; const char *desc; } test_vec;

static const test_vec VECTORS[] = {
    /*
     * Non-octal WITH null terminator — two lengths to cover both 8-byte
     * fields (uid/gid/mode) and 12-byte fields (size/mtime).
     *
     * The critical split:
     *   - Extractors that check null-termination first (obfusc02 pattern)
     *     PASS the null check here, then reach the octal parser.  If that
     *     parser crashes on a bad digit (e.g. NULL-deref instead of error)
     *     this is the vector that triggers it.
     *   - The no-null variants further down are trimmed to field width and
     *     hit the null-termination rejection path instead — so they test a
     *     completely different code branch.
     * Both sets are needed; neither alone covers both bugs.
     *
     * Digits '9' and '8' are the smallest non-octal decimal digits.
     * Letter 'A' covers extractors that only reject digits > 7 but not letters.
     */
    /* 8-byte field width: 7 bad chars + implicit NUL */
    { "9999999",       8,  "non-octal '9', null-terminated (7+NUL, 8-byte fields)"  },
    { "8888888",       8,  "non-octal '8', null-terminated (7+NUL, 8-byte fields)"  },
    { "AAAAAAA",       8,  "hex letter 'A', null-terminated (7+NUL, 8-byte fields)" },
    /* 12-byte field width: 11 bad chars + implicit NUL */
    { "99999999999",  12,  "non-octal '9', null-terminated (11+NUL, 12-byte fields)" },
    { "88888888888",  12,  "non-octal '8', null-terminated (11+NUL, 12-byte fields)" },
    { "AAAAAAAAAAA",  12,  "hex letter 'A', null-terminated (11+NUL, 12-byte fields)"},
    /*
     * Non-octal WITHOUT null terminator.
     * Trimmed to field width by fuzz_field, so no NUL is written.
     * Hits extractors that skip null-termination and parse raw bytes,
     * or that use strncpy/memcpy and read non-octal content directly.
     */
    { "99999999999",  12, "non-octal '9', no null (trimmed to field width)"          },
    { "FFFFFFFFFFF",  12, "hex letters, no null"                                     },
    /* whitespace — strtol/sscanf may return 0, negative, or undefined */
    { "           ",  12, "all spaces"                                               },
    /* negative values — strtol returns negative; extractors using signed
     * int may accept them and seek/allocate a negative size */
    { "-0000000001",  12, "negative value (-1)"                                      },
    { "-7777777777",  12, "negative max"                                             },
    /* boundary and overflow */
    { "77777777777",  12, "max 11-digit octal, no null"                              },
    { "17777777777",  12, "INT_MAX in octal"                                         },
    { "20000000000",  12, "INT_MAX+1 in octal"                                       },
    /* fully degenerate */
    { "\0\0\0\0\0\0\0\0\0\0\0\0", 12, "all NUL bytes"                               },
    { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 12, "all 0xFF bytes"       },
};

#define N_VECTORS (int)(sizeof VECTORS / sizeof VECTORS[0])

/* ── generic field fuzzer ──────────────────────────────────────────── */

static void fuzz_field(char *extractor, int *sc, const field_desc *fd) {
    for (int i = 0; i < N_VECTORS; i++) {
        FILE *f = fopen("archive.tar", "wb");
        struct tar_t h;
        init_header(&h, "test.txt", '0', 0);
        /* write at most fd->width bytes so we never overrun the field */
        size_t w = VECTORS[i].len < (size_t)fd->width
                   ? VECTORS[i].len : (size_t)fd->width;
        fd->set(&h, VECTORS[i].value, w);
        calculate_checksum(&h);
        write_tar(f, &h, NULL, 0);
        write_end(f);
        fclose(f);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[%s] %s\n", fd->label, VECTORS[i].desc);
            save_success("archive.tar", (*sc)++);
        }
    }
}

/* ── size-specific extra cases (need real data buffers) ─────────────── */

static void fuzz_size_extras(char *extractor, int *sc) {
    FILE *f;
    struct tar_t h;

    /* 1 MB of real data – allocation / read overflow */
    int sz = 1024 * 1024;
    char *data = malloc(sz);
    if (data) {
        memset(data, 'A', sz);
        f = fopen("archive.tar", "wb");
        init_header(&h, "big.txt", '0', sz);
        write_tar(f, &h, data, sz);
        write_end(f);
        fclose(f);
        free(data);
        if (run_extractor(extractor, "archive.tar") == 1) {
            printf("[size] 1 MB real data\n");
            save_success("archive.tar", (*sc)++);
        }
    }

    /* size = 0 with a regular file – edge but valid */
    f = fopen("archive.tar", "wb");
    init_header(&h, "empty.txt", '0', 0);
    memcpy(h.size, "00000000000\0", 12);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[size] zero size regular file\n");
        save_success("archive.tar", (*sc)++);
    }

    /* 12 bytes of '7' with no NUL – read past field boundary */
    f = fopen("archive.tar", "wb");
    init_header(&h, "test.txt", '0', 0);
    memset(h.size, '7', 12);
    calculate_checksum(&h);
    write_tar(f, &h, NULL, 0);
    write_end(f);
    fclose(f);
    if (run_extractor(extractor, "archive.tar") == 1) {
        printf("[size] 12 '7's, no null terminator\n");
        save_success("archive.tar", (*sc)++);
    }
}

/* ── public entry point ────────────────────────────────────────────── */

void fuzz_numeric_fields(char *extractor, int *sc) {
    static const field_desc FIELDS[] = {
        { "size",  set_size,  12 },
        { "mtime", set_mtime, 12 },
        { "uid",   set_uid,    8 },
        { "gid",   set_gid,    8 },
        { "mode",  set_mode,   8 },
    };
    int nf = (int)(sizeof FIELDS / sizeof FIELDS[0]);

    for (int i = 0; i < nf; i++)
        fuzz_field(extractor, sc, &FIELDS[i]);

    /* size has additional cases that require actual data allocation */
    fuzz_size_extras(extractor, sc);
}