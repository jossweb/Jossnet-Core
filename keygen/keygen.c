/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */

#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "keygen.h"
#include "../common/common.h"
#ifdef _WIN32
	#include <direct.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <unistd.h>
    #include <sys/types.h>
    #define MKDIR(path) mkdir(path, 0700)
#endif

#include <sys/stat.h>

#define PSK_LENGTH 42

const char* salt[] = {
    "jossnet_salt_001", "jossnet_salt_002", "jossnet_salt_003", "jossnet_salt_004",
    "jossnet_salt_005", "jossnet_salt_006", "jossnet_salt_007", "jossnet_salt_008",
    "jossnet_salt_009", "jossnet_salt_010", "jossnet_salt_011", "jossnet_salt_012",
    "jossnet_salt_013", "jossnet_salt_014", "jossnet_salt_015", "jossnet_salt_016",
    "jossnet_salt_017", "jossnet_salt_018", "jossnet_salt_019", "jossnet_salt_020",
    "jossnet_salt_021", "jossnet_salt_022", "jossnet_salt_023", "jossnet_salt_024",
    "jossnet_salt_025", "jossnet_salt_026", "jossnet_salt_027", "jossnet_salt_028",
    "jossnet_salt_029", "jossnet_salt_030", "jossnet_salt_031", "jossnet_salt_032",
    "jossnet_salt_033", "jossnet_salt_034", "jossnet_salt_035", "jossnet_salt_036",
    "jossnet_salt_037", "jossnet_salt_038", "jossnet_salt_039", "jossnet_salt_040",
    "jossnet_salt_041", "jossnet_salt_042", "jossnet_salt_043", "jossnet_salt_044",
    "jossnet_salt_045", "jossnet_salt_046", "jossnet_salt_047", "jossnet_salt_048",
    "jossnet_salt_049", "jossnet_salt_050", "jossnet_salt_051", "jossnet_salt_052",
    "jossnet_salt_053", "jossnet_salt_054", "jossnet_salt_055", "jossnet_salt_056",
    "jossnet_salt_057", "jossnet_salt_058", "jossnet_salt_059", "jossnet_salt_060",
    "jossnet_salt_061", "jossnet_salt_062", "jossnet_salt_063", "jossnet_salt_064",
    "jossnet_salt_065", "jossnet_salt_066", "jossnet_salt_067", "jossnet_salt_068",
    "jossnet_salt_069", "jossnet_salt_070", "jossnet_salt_071", "jossnet_salt_072",
    "jossnet_salt_073", "jossnet_salt_074", "jossnet_salt_075", "jossnet_salt_076",
    "jossnet_salt_077", "jossnet_salt_078", "jossnet_salt_079", "jossnet_salt_080",
    "jossnet_salt_081", "jossnet_salt_082", "jossnet_salt_083", "jossnet_salt_084",
    "jossnet_salt_085", "jossnet_salt_086", "jossnet_salt_087", "jossnet_salt_088",
    "jossnet_salt_089", "jossnet_salt_090", "jossnet_salt_091", "jossnet_salt_092",
    "jossnet_salt_093", "jossnet_salt_094", "jossnet_salt_095", "jossnet_salt_096",
    "jossnet_salt_097", "jossnet_salt_098", "jossnet_salt_099", "jossnet_salt_100",
    "jossnet_salt_101", "jossnet_salt_102", "jossnet_salt_103", "jossnet_salt_104",
    "jossnet_salt_105", "jossnet_salt_106", "jossnet_salt_107", "jossnet_salt_108",
    "jossnet_salt_109", "jossnet_salt_110", "jossnet_salt_111", "jossnet_salt_112",
    "jossnet_salt_113", "jossnet_salt_114", "jossnet_salt_115", "jossnet_salt_116",
    "jossnet_salt_117", "jossnet_salt_118", "jossnet_salt_119", "jossnet_salt_120",
    "jossnet_salt_121", "jossnet_salt_122", "jossnet_salt_123", "jossnet_salt_124",
    "jossnet_salt_125", "jossnet_salt_126", "jossnet_salt_127", "jossnet_salt_128"
};
const int salt_count = 128;

int save_private_key(const char *filename, const uint8_t *key, size_t len);
int save_public_key(const char *filename, const uint8_t *key, size_t len);

const char* secondary_secure_string  = "Jossnet2025Server";

char* build_seed(int server_id, const char* principal_secure_string , const char* secondary_secure_string) {
    char server_id_str[16];
    snprintf(server_id_str, sizeof(server_id_str), "%d", server_id);
    size_t total_len = strlen(server_id_str) + strlen(principal_secure_string) + strlen(secondary_secure_string) + 1;
    char* seed = malloc(total_len);
    if (!seed) return NULL;

    snprintf(seed, total_len, "%s%s%s", server_id_str, principal_secure_string , secondary_secure_string);
    return seed;
}
void define_psk(int server_id, const char* principal_secure_string, const int salt_index, uint8_t *psk_out) {
    char* seed = build_seed(server_id, principal_secure_string, secondary_secure_string);
    if (!seed) {
        memset(psk_out, 0, PSK_LENGTH);
        return;
    }
    derive_psk_from_seed(seed, "ton_salt", psk_out, PSK_LENGTH);
    free(seed);
}
int gen_keys(KeyFile key)
{
    NoiseDHState *dh;
    uint8_t *priv_key = 0;
    size_t priv_key_len = 0;
    uint8_t *pub_key = 0;
    size_t pub_key_len = 0;
    int ok = 1;
    int err;

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 0;
    }
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        printf("Keys have been generated at : %s\n", cwd);
    else
        printf("error getting current directory\n");

    err = noise_dhstate_new_by_name(&dh, key.algorithm);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(key.algorithm, err);
        return 0;
    }

    err = noise_dhstate_generate_keypair(dh);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("generate keypair", err);
        noise_dhstate_free(dh);
        return 0;
    }
    /* Fetch the keypair to be saved */
    priv_key_len = noise_dhstate_get_private_key_length(dh);
    pub_key_len = noise_dhstate_get_public_key_length(dh);
    priv_key = (uint8_t *)malloc(priv_key_len);
    pub_key = (uint8_t *)malloc(pub_key_len);
    if (!priv_key || !pub_key) {
        fprintf(stderr, "Out of memory\n");
        return 0;
    }
    err = noise_dhstate_get_keypair
        (dh, priv_key, priv_key_len, pub_key, pub_key_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("get keypair for saving", err);
        ok = 0;
    }
    /* Save the keys */
    if (ok)
        ok = save_private_key(key.private_key, priv_key, priv_key_len);
    if (ok)
        ok = save_public_key(key.public_key, pub_key, pub_key_len);

    /* Clean up */
    noise_dhstate_free(dh);
    noise_free(priv_key, priv_key_len);
    noise_free(pub_key, pub_key_len);
    if (!ok) {
        unlink(key.private_key);
        unlink(key.public_key);
    }
    return 1;
}
/* Saves a binary private key to a file.  Returns non-zero if OK. */
int save_private_key(const char *filename, const uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "wb");
    size_t posn;
    if (!file) {
        perror(filename);
        return 0;
    }
    for (posn = 0; posn < len; ++posn)
        putc(key[posn], file);
    fclose(file);
    return 1;
}

/* Saves a base64-encoded public key to a file.  Returns non-zero if OK. */
int save_public_key(const char *filename, const uint8_t *key, size_t len)
{
    static char const base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    FILE *file = fopen(filename, "wb");
    size_t posn = 0;
    uint32_t group;
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((len - posn) >= 3) {
        group = (((uint32_t)(key[posn])) << 16) |
                (((uint32_t)(key[posn + 1])) << 8) |
                 ((uint32_t)(key[posn + 2]));
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc(base64_chars[(group >> 6) & 0x3F], file);
        putc(base64_chars[group & 0x3F], file);
        posn += 3;
    }
    if ((len - posn) == 2) {
        group = (((uint32_t)(key[posn])) << 16) |
                (((uint32_t)(key[posn + 1])) << 8);
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc(base64_chars[(group >> 6) & 0x3F], file);
        putc('=', file);
    } else if ((len - posn) == 1) {
        group = ((uint32_t)(key[posn])) << 16;
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc('=', file);
        putc('=', file);
    }
    fclose(file);
    return 1;
}