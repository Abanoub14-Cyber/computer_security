#ifndef EXTRACTOR_H
#define EXTRACTOR_H

// return 1 if crahs detected
int  run_extractor(char *extractor, char *tarfile);

// copy tarfile in success tar
void save_success(char *tarfile, int index);

#endif
