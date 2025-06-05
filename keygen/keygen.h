//
// Created by FIGUEIRAS Jossua on 02/06/2025.
//

#ifndef KEYGEN_H
#define KEYGEN_H

#endif //KEYGEN_H

typedef struct {
    const char *algorithm;
    const char *private_key;
    const char *public_key;
} KeyFile;

int gen_keys(KeyFile key);