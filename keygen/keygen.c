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
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include "keygen.h"

#define PSK_LENGTH 42


int save_private_key(const char *filename, const uint8_t *key, size_t len);
int save_public_key(const char *filename, const uint8_t *key, size_t len);
int gen_psk();

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

    mkdir("keys", 0700);
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        printf("Clés générées dans le dossier : %s\n", cwd);
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
    return ok ? 0 : 1;
}
int gen_psk() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char psk[PSK_LENGTH + 1];

    // Init seed
    srand((unsigned int)time(NULL));

    for (int i = 0; i < PSK_LENGTH; i++) {
        psk[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    psk[PSK_LENGTH] = '\0';
    FILE *f = fopen("psk", "w");
    if (!f) {
        perror("Error: can't generate psk");
        return 0;
    }
    fprintf(f, "%s\n", psk);
    fclose(f);
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