#ifndef TAR_UTILS_H
#define TAR_UTILS_H

#include <stdio.h>
#include "help.h"

// tar header structure (512 bytes)
void init_header(struct tar_t *header, const char *name, char typeflag, int size);

// Writes a header + data blocks to a tar file.
void write_tar(FILE *f, struct tar_t *header, const char *data, int size);

void write_end(FILE *f);

#endif
