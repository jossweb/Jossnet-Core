/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */

#ifndef __JOSSNET_COMMON_H__
#define __JOSSNET_COMMON_H__

#include <noise/protocol.h>

#define JOSSNET_PSK_DISABLED           0x00
#define JOSSNET_PSK_ENABLED            0x01

#define JOSSNET_PATTERN_NN             0x00
#define JOSSNET_PATTERN_KN             0x01
#define JOSSNET_PATTERN_NK             0x02
#define JOSSNET_PATTERN_KK             0x03
#define JOSSNET_PATTERN_NX             0x04
#define JOSSNET_PATTERN_KX             0x05
#define JOSSNET_PATTERN_XN             0x06
#define JOSSNET_PATTERN_IN             0x07
#define JOSSNET_PATTERN_XK             0x08
#define JOSSNET_PATTERN_IK             0x09
#define JOSSNET_PATTERN_XX             0x0A
#define JOSSNET_PATTERN_IX             0x0B
#define JOSSNET_PATTERN_HFS            0x80

#define JOSSNET_CIPHER_CHACHAPOLY      0x00
#define JOSSNET_CIPHER_AESGCM          0x01

#define JOSSNET_DH_25519               0x00
#define JOSSNET_DH_448                 0x01
#define JOSSNET_DH_NEWHOPE             0x02
#define JOSSNET_DH_MASK                0x0F

#define JOSSNET_HYBRID_NONE            0x00
#define JOSSNET_HYBRID_25519           0x10
#define JOSSNET_HYBRID_448             0x20
#define JOSSNET_HYBRID_NEWHOPE         0x30
#define JOSSNET_HYBRID_MASK            0xF0

#define JOSSNET_HASH_SHA256            0x00
#define JOSSNET_HASH_SHA512            0x01
#define JOSSNET_HASH_BLAKE2s           0x02
#define JOSSNET_HASH_BLAKE2b           0x03

typedef struct
{
    uint8_t psk;
    uint8_t pattern;
    uint8_t cipher;
    uint8_t dh;
    uint8_t hash;

} JossnetProtocolId;

extern int jossnet_verbose;

int jossnet_get_protocol_id(JossnetProtocolId *id, const char *name);
int jossnet_to_noise_protocol_id(NoiseProtocolId *nid, const JossnetProtocolId *id);

int jossnet_load_private_key(const char *filename, uint8_t *key, size_t len);
int jossnet_load_public_key(const char *content, uint8_t *key, size_t len, int from_file);

int jossnet_connect(const char *hostname, int port);
int jossnet_accept(int port);

int jossnet_recv_exact(int fd, uint8_t *packet, size_t len);
size_t jossnet_recv(int fd, uint8_t *packet, size_t max_len);
int jossnet_send(int fd, const uint8_t *packet, size_t len);
void jossnet_close(int fd);

#endif
