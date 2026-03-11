#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "tar_utils.h"
#include "help.h"

/**
 * Initializes a tar header with valid POSIX 1003.1-1990 defaults.
 *
 * This creates a header that a conforming extractor should accept:
 *  - magic  = "ustar\0"  (POSIX magic)
 *  - version = "00"       (POSIX version)
 *  - mode   = "0000664\0" (regular file permissions, octal)
 *  - uid/gid = "0001750\0" (typical user/group)
 *  - mtime  = a fixed valid timestamp
 *  - uname/gname = "user" / "group"
 *  - chksum is computed at the end
 */
void init_header(struct tar_t *header, const char *name, char typeflag, int size) {
    /* Start with a completely zeroed header (512 bytes) */
    memset(header, 0, sizeof(struct tar_t));

    /* File name: copy at most 99 chars + leave room for '\0' */
    if (name != NULL)
        strncpy(header->name, name, 100);

    /* File mode: rw-rw-r-- in octal */
    strncpy(header->mode, "0000664", 8);

    /* Owner/group ID: typical non-root user */
    strncpy(header->uid, "0001750", 8);
    strncpy(header->gid, "0001750", 8);

    /* File size in 11-digit octal + null terminator */
    snprintf(header->size, 12, "%011o", size);

    /* Modification time: a valid fixed timestamp (2024-01-01 ~) */
    strncpy(header->mtime, "14717572600", 12);

    /* Type flag */
    header->typeflag = typeflag;

    /* POSIX magic and version — this is what makes it a "ustar" archive */
    memcpy(header->magic, "ustar\0", 6);   /* "ustar" + NUL byte */
    header->version[0] = '0';
    header->version[1] = '0';

    /* Owner/group name strings */
    strncpy(header->uname, "user", 32);
    strncpy(header->gname, "group", 32);

    /* Compute and write the checksum (fills header->chksum) */
    calculate_checksum(header);
}

/**
 * Writes a header + data blocks to a tar file.
 *
 * In the tar format, after every 512-byte header, the file data follows
 * in 512-byte blocks.  If the data doesn't fill a whole block, the
 * remainder is zero-padded.
 */
void write_tar(FILE *f, struct tar_t *header, const char *data, int size) {
    /* Write the 512-byte header */
    fwrite(header, 1, 512, f);

    /* Write the data blocks (if any) */
    if (data != NULL && size > 0) {
        fwrite(data, 1, size, f);

        /* Pad to the next 512-byte boundary */
        int remainder = size % 512;
        if (remainder != 0) {
            char padding[512] = {0};
            fwrite(padding, 1, 512 - remainder, f);
        }
    }
}

/**
 * Writes the end-of-archive marker.
 *
 * A valid tar archive ends with two consecutive 512-byte blocks filled
 * with zeros.  This tells the extractor "no more entries".
 */
void write_end(FILE *f) {
    char zeros[1024] = {0};   /* 2 × 512 bytes */
    fwrite(zeros, 1, 1024, f);
}
