#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "tar_utils.h"
#include "help.h"


void init_header(struct tar_t *header, const char *name, char typeflag, int size) {
    memset(header, 0, sizeof(struct tar_t));

    if (name != NULL)
        strncpy(header->name, name, 100);

    strncpy(header->mode, "0000664", 8);

    strncpy(header->uid, "0001750", 8);
    strncpy(header->gid, "0001750", 8);

    snprintf(header->size, 12, "%011o", size);

    strncpy(header->mtime, "14717572600", 12);

    header->typeflag = typeflag;

    memcpy(header->magic, "ustar\0", 6);  
    header->version[0] = '0';
    header->version[1] = '0';

    strncpy(header->uname, "user", 32);
    strncpy(header->gname, "group", 32);

    calculate_checksum(header);
}


void write_tar(FILE *f, struct tar_t *header, const char *data, int size) {
    fwrite(header, 1, 512, f);

    if (data != NULL && size > 0) {
        fwrite(data, 1, size, f);

        int remainder = size % 512;
        if (remainder != 0) {
            char padding[512] = {0};
            fwrite(padding, 1, 512 - remainder, f);
        }
    }
}


void write_end(FILE *f) {
    char zeros[1024] = {0};   
    fwrite(zeros, 1, 1024, f);
}
