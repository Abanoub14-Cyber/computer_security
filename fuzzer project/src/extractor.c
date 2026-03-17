#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "extractor.h"


int run_extractor(char *extractor, char *tarfile) {
    char abs_extractor[512];
    char abs_tar[512];

    if (extractor[0] != '/')
        snprintf(abs_extractor, sizeof(abs_extractor), "%s/%s",
                 getcwd(NULL, 0), extractor);
    else
        snprintf(abs_extractor, sizeof(abs_extractor), "%s", extractor);

    if (tarfile[0] != '/')
        snprintf(abs_tar, sizeof(abs_tar), "%s/%s",
                 getcwd(NULL, 0), tarfile);
    else
        snprintf(abs_tar, sizeof(abs_tar), "%s", tarfile);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "TMPD=$(mktemp -d) && cp \"%s\" \"$TMPD/archive.tar\" && "
             "cd \"$TMPD\" && \"%s\" archive.tar 2>/dev/null; EC=$?; "
             "rm -rf \"$TMPD\"; exit $EC",
             abs_tar, abs_extractor);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;

    char buf[64];
    int rv = 0;

    if (fgets(buf, sizeof(buf), fp) != NULL)
        if (strncmp(buf, "*** The program has crashed ***\n", 32) == 0)
            rv = 1;

    pclose(fp);
    return rv;
}

void save_success(char *tarfile, int index) {
    char dest[64];
    snprintf(dest, sizeof(dest), "success_%03d.tar", index);

    FILE *src = fopen(tarfile, "rb");
    FILE *dst = fopen(dest, "wb");
    if (!src || !dst) {
        if (src) fclose(src);
        if (dst) fclose(dst);
        return;
    }

    char buf[512];
    int n;
    while ((n = fread(buf, 1, 512, src)) > 0)
        fwrite(buf, 1, n, dst);

    fclose(src);
    fclose(dst);

}
