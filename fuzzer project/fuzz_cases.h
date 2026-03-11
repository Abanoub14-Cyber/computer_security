#ifndef FUZZ_CASES_H
#define FUZZ_CASES_H

/* All numeric fields (size, mtime, uid, gid, mode) in one function */
void fuzz_numeric_fields(char *extractor, int *sc);

void fuzz_typeflag(char *extractor, int *sc);  /* typeflag + combos merged */
void fuzz_name(char *extractor, int *sc);
void fuzz_linkname(char *extractor, int *sc);
void fuzz_checksum(char *extractor, int *sc);
void fuzz_magic(char *extractor, int *sc);
void fuzz_structure(char *extractor, int *sc);
void fuzz_many_files(char *extractor, int *sc);
void fuzz_uname_gname(char *extractor, int *sc);

#endif
