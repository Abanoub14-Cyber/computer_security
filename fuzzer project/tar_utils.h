#ifndef TAR_UTILS_H
#define TAR_UTILS_H

#include <stdio.h>
#include "help.h"

/**
 * Initializes a tar header with valid POSIX 1003.1-1990 defaults.
 * @param header   Pointer to the tar header struct to fill.
 * @param name     Filename to store in the header (max 100 chars).
 * @param typeflag Type of entry: '0' regular, '5' directory, '2' symlink, etc.
 * @param size     Size of the file data in bytes.
 */
void init_header(struct tar_t *header, const char *name, char typeflag, int size);

/**
 * Writes a complete tar entry (header + optional data blocks) to a file.
 * Data is padded to a 512-byte boundary as required by the tar format.
 * @param f      Open FILE* to write to (binary mode).
 * @param header Pointer to the tar header (checksum is computed automatically).
 * @param data   Pointer to file data (can be NULL if size is 0).
 * @param size   Number of data bytes to write.
 */
void write_tar(FILE *f, struct tar_t *header, const char *data, int size);

/**
 * Writes the end-of-archive marker: two consecutive 512-byte blocks of zeros.
 * @param f Open FILE* to write to (binary mode).
 */
void write_end(FILE *f);

#endif
