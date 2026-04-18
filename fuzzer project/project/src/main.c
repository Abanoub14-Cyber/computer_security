#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include "extractor.h"
#include "fuzz_cases.h"

static void fuzz_all(char *extractor) {
    int sc = 0;

    fuzz_numeric_fields(extractor, &sc);   
    fuzz_typeflag(extractor, &sc);         
    fuzz_name(extractor, &sc);
    fuzz_linkname(extractor, &sc);
    fuzz_checksum(extractor, &sc);
    fuzz_magic(extractor, &sc);
    fuzz_structure(extractor, &sc);
    fuzz_many_files(extractor, &sc);
    fuzz_uname_gname(extractor, &sc);

    printf("[*] Total crashes found: %d\n", sc);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <extractor>\n", argv[0]);
        return -1;
    }


    printf("[*] Starting fuzzer on: %s\n", argv[1]);
    fuzz_all(argv[1]);
    printf("[*] Fuzzing done.\n");
    return 0;
}
