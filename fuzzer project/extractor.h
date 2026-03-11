#ifndef EXTRACTOR_H
#define EXTRACTOR_H

/* Lance l'extracteur sur tarfile, retourne 1 si crash détecté */
int  run_extractor(char *extractor, char *tarfile);

/* Copie tarfile en success_XXX.tar */
void save_success(char *tarfile, int index);

#endif
