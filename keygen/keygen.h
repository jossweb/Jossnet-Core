/*
* Modified and adapted for the Jossnet project
* © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
*/

#ifndef KEYGEN_H
#define KEYGEN_H

#endif //KEYGEN_H

typedef struct {
    const char *algorithm;
    const char *private_key;
    const char *public_key;
} KeyFile;

int gen_keys(KeyFile key);

extern const int salt_count;
void define_psk(int server_id, const char* principal_secure_string, const int salt_index, uint8_t *psk_out);
