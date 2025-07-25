/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 *
 * This file contains portions of code derived from the Noise-C project:
 * https://github.com/rweather/noise-c
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Licensed under the MIT License.
 */
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if defined(__WIN32__) || defined(WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
typedef BOOL sockopt_type;
#define MSG_NOSIGNAL 0
#undef HAVE_POLL
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#if HAVE_POLL
#include <poll.h>
#endif
#include <errno.h>
#define closesocket(x)  close((x))
typedef int sockopt_type;
#endif
#define MAX_DH_KEY_LEN 2048

int jossnet_verbose = 0;

void psk_to_hex(const uint8_t *psk, size_t psk_len, char *out) {
    for (size_t i = 0; i < psk_len; ++i) {
        sprintf(out + (i * 2), "%02x", psk[i]);
    }
    out[psk_len * 2] = '\0';
}
void derive_psk_from_seed(const char *seed, const char *salt, uint8_t *psk, size_t psk_len) {
    NoiseHashState *hash;
    int err;

    err = noise_hashstate_new_by_id(&hash, NOISE_HASH_SHA256);
    if (err != NOISE_ERROR_NONE) {
        return;
    }
    err = noise_hashstate_pbkdf2(hash, (const uint8_t *)seed, strlen(seed), (const uint8_t *)salt, strlen(salt), 10000,
		psk, psk_len);

    noise_hashstate_free(hash);
}
int write_in_file(const char *path, const char* content) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("Error, can't open : %s");
        return 0;
    }
    if (fputs(content, f) == EOF) {
        perror("Error can't write in: %s");
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}
char* read_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error can't open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    rewind(file);

    char* buffer = malloc(length + 1);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        return NULL;
    }
    fread(buffer, 1, length, file);
    buffer[length] = '\0';

    fclose(file);
    return buffer;
}
int jossnet_get_protocol_id(JossnetProtocolId *id, const char *name)
{
    NoiseProtocolId nid;
    int ok = 1;

    memset(id, 0, sizeof(JossnetProtocolId));
    if (noise_protocol_name_to_id(&nid, name, strlen(name)) != NOISE_ERROR_NONE)
        return 0;

    switch (nid.prefix_id) {
    case NOISE_PREFIX_STANDARD:     id->psk = JOSSNET_PSK_DISABLED; break;
    case NOISE_PREFIX_PSK:          id->psk = JOSSNET_PSK_ENABLED; break;
    default:                        ok = 0; break;
    }

    switch (nid.pattern_id) {
    case NOISE_PATTERN_NN:          id->pattern = JOSSNET_PATTERN_NN; break;
    case NOISE_PATTERN_KN:          id->pattern = JOSSNET_PATTERN_KN; break;
    case NOISE_PATTERN_NK:          id->pattern = JOSSNET_PATTERN_NK; break;
    case NOISE_PATTERN_KK:          id->pattern = JOSSNET_PATTERN_KK; break;
    case NOISE_PATTERN_NX:          id->pattern = JOSSNET_PATTERN_NX; break;
    case NOISE_PATTERN_KX:          id->pattern = JOSSNET_PATTERN_KX; break;
    case NOISE_PATTERN_XN:          id->pattern = JOSSNET_PATTERN_XN; break;
    case NOISE_PATTERN_IN:          id->pattern = JOSSNET_PATTERN_IN; break;
    case NOISE_PATTERN_XK:          id->pattern = JOSSNET_PATTERN_XK; break;
    case NOISE_PATTERN_IK:          id->pattern = JOSSNET_PATTERN_IK; break;
    case NOISE_PATTERN_XX:          id->pattern = JOSSNET_PATTERN_XX; break;
    case NOISE_PATTERN_IX:          id->pattern = JOSSNET_PATTERN_IX; break;
    case NOISE_PATTERN_NN_HFS:      id->pattern = JOSSNET_PATTERN_NN | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_KN_HFS:      id->pattern = JOSSNET_PATTERN_KN | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_NK_HFS:      id->pattern = JOSSNET_PATTERN_NK | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_KK_HFS:      id->pattern = JOSSNET_PATTERN_KK | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_NX_HFS:      id->pattern = JOSSNET_PATTERN_NX | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_KX_HFS:      id->pattern = JOSSNET_PATTERN_KX | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_XN_HFS:      id->pattern = JOSSNET_PATTERN_XN | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_IN_HFS:      id->pattern = JOSSNET_PATTERN_IN | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_XK_HFS:      id->pattern = JOSSNET_PATTERN_XK | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_IK_HFS:      id->pattern = JOSSNET_PATTERN_IK | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_XX_HFS:      id->pattern = JOSSNET_PATTERN_XX | JOSSNET_PATTERN_HFS; break;
    case NOISE_PATTERN_IX_HFS:      id->pattern = JOSSNET_PATTERN_IX | JOSSNET_PATTERN_HFS; break;
    default:                        ok = 0; break;
    }

    switch (nid.cipher_id) {
    case NOISE_CIPHER_CHACHAPOLY:   id->cipher = JOSSNET_CIPHER_CHACHAPOLY; break;
    case NOISE_CIPHER_AESGCM:       id->cipher = JOSSNET_CIPHER_AESGCM; break;
    default:                        ok = 0; break;
    }

    switch (nid.dh_id) {
    case NOISE_DH_CURVE25519:       id->dh = JOSSNET_DH_25519; break;
    case NOISE_DH_CURVE448:         id->dh = JOSSNET_DH_448; break;
    case NOISE_DH_NEWHOPE:          id->dh = JOSSNET_DH_NEWHOPE; break;
    default:                        ok = 0; break;
    }

    switch (nid.hybrid_id) {
    case NOISE_DH_CURVE25519:       id->dh |= JOSSNET_HYBRID_25519; break;
    case NOISE_DH_CURVE448:         id->dh |= JOSSNET_HYBRID_448; break;
    case NOISE_DH_NEWHOPE:          id->dh |= JOSSNET_HYBRID_NEWHOPE; break;
    case NOISE_DH_NONE:             break;
    default:                        ok = 0; break;
    }

    switch (nid.hash_id) {
    case NOISE_HASH_SHA256:         id->hash = JOSSNET_HASH_SHA256; break;
    case NOISE_HASH_SHA512:         id->hash = JOSSNET_HASH_SHA512; break;
    case NOISE_HASH_BLAKE2s:        id->hash = JOSSNET_HASH_BLAKE2s; break;
    case NOISE_HASH_BLAKE2b:        id->hash = JOSSNET_HASH_BLAKE2b; break;
    default:                        ok = 0; break;
    }

    return ok;
}

/* Convert an JOSSNET protocol id into a Noise protocol id */
int jossnet_to_noise_protocol_id(NoiseProtocolId *nid, const JossnetProtocolId *id)
{
    int ok = 1;

    memset(nid, 0, sizeof(NoiseProtocolId));

    switch (id->psk) {
    case JOSSNET_PSK_DISABLED:         nid->prefix_id = NOISE_PREFIX_STANDARD; break;
    case JOSSNET_PSK_ENABLED:          nid->prefix_id = NOISE_PREFIX_PSK; break;
    default:                        ok = 0;
    }

    switch (id->pattern) {
    case JOSSNET_PATTERN_NN:           nid->pattern_id = NOISE_PATTERN_NN; break;
    case JOSSNET_PATTERN_KN:           nid->pattern_id = NOISE_PATTERN_KN; break;
    case JOSSNET_PATTERN_NK:           nid->pattern_id = NOISE_PATTERN_NK; break;
    case JOSSNET_PATTERN_KK:           nid->pattern_id = NOISE_PATTERN_KK; break;
    case JOSSNET_PATTERN_NX:           nid->pattern_id = NOISE_PATTERN_NX; break;
    case JOSSNET_PATTERN_KX:           nid->pattern_id = NOISE_PATTERN_KX; break;
    case JOSSNET_PATTERN_XN:           nid->pattern_id = NOISE_PATTERN_XN; break;
    case JOSSNET_PATTERN_IN:           nid->pattern_id = NOISE_PATTERN_IN; break;
    case JOSSNET_PATTERN_XK:           nid->pattern_id = NOISE_PATTERN_XK; break;
    case JOSSNET_PATTERN_IK:           nid->pattern_id = NOISE_PATTERN_IK; break;
    case JOSSNET_PATTERN_XX:           nid->pattern_id = NOISE_PATTERN_XX; break;
    case JOSSNET_PATTERN_IX:           nid->pattern_id = NOISE_PATTERN_IX; break;
    case JOSSNET_PATTERN_NN | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_NN_HFS; break;
    case JOSSNET_PATTERN_KN | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_KN_HFS; break;
    case JOSSNET_PATTERN_NK | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_NK_HFS; break;
    case JOSSNET_PATTERN_KK | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_KK_HFS; break;
    case JOSSNET_PATTERN_NX | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_NX_HFS; break;
    case JOSSNET_PATTERN_KX | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_KX_HFS; break;
    case JOSSNET_PATTERN_XN | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_XN_HFS; break;
    case JOSSNET_PATTERN_IN | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_IN_HFS; break;
    case JOSSNET_PATTERN_XK | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_XK_HFS; break;
    case JOSSNET_PATTERN_IK | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_IK_HFS; break;
    case JOSSNET_PATTERN_XX | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_XX_HFS; break;
    case JOSSNET_PATTERN_IX | JOSSNET_PATTERN_HFS:    nid->pattern_id = NOISE_PATTERN_IX_HFS; break;
    default:                        ok = 0;
    }

    switch (id->cipher) {
    case JOSSNET_CIPHER_CHACHAPOLY:    nid->cipher_id = NOISE_CIPHER_CHACHAPOLY; break;
    case JOSSNET_CIPHER_AESGCM:        nid->cipher_id = NOISE_CIPHER_AESGCM; break;
    default:                        ok = 0;
    }

    switch (id->dh & JOSSNET_DH_MASK) {
    case JOSSNET_DH_25519:             nid->dh_id = NOISE_DH_CURVE25519; break;
    case JOSSNET_DH_448:               nid->dh_id = NOISE_DH_CURVE448; break;
    case JOSSNET_DH_NEWHOPE:           nid->dh_id = NOISE_DH_NEWHOPE; break;
    default:                        ok = 0;
    }

    switch (id->dh & JOSSNET_HYBRID_MASK) {
    case JOSSNET_HYBRID_25519:         nid->hybrid_id = NOISE_DH_CURVE25519; break;
    case JOSSNET_HYBRID_448:           nid->hybrid_id = NOISE_DH_CURVE448; break;
    case JOSSNET_HYBRID_NEWHOPE:       nid->hybrid_id = NOISE_DH_NEWHOPE; break;
    case JOSSNET_HYBRID_NONE:          nid->hybrid_id = NOISE_DH_NONE; break;
    default:                        ok = 0;
    }

    switch (id->hash) {
    case JOSSNET_HASH_SHA256:          nid->hash_id = NOISE_HASH_SHA256; break;
    case JOSSNET_HASH_SHA512:          nid->hash_id = NOISE_HASH_SHA512; break;
    case JOSSNET_HASH_BLAKE2s:         nid->hash_id = NOISE_HASH_BLAKE2s; break;
    case JOSSNET_HASH_BLAKE2b:         nid->hash_id = NOISE_HASH_BLAKE2b; break;
    default:                        ok = 0;
    }

    return ok;
}

/* Loads a binary private key from a file.  Returns non-zero if OK. */
int jossnet_load_private_key(const char *filename, uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "rb");
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "private key length is not supported\n");
        return 0;
    }
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (posn >= len) {
            fclose(file);
            fprintf(stderr, "%s: private key value is too long\n", filename);
            return 0;
        }
        key[posn++] = (uint8_t)ch;
    }
    if (posn < len) {
        fclose(file);
        fprintf(stderr, "%s: private key value is too short\n", filename);
        return 0;
    }
    fclose(file);
    return 1;
}

/* Loads a base64-encoded public key.  Returns non-zero if OK. */
int jossnet_load_public_key(const char *content, uint8_t *key, size_t len, int from_file)
{
    FILE *file;
    if(from_file){
        file = fopen(content, "rb");
    }else{
        file = fmemopen((void*)content, strlen(content), "rb");
    }
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    if (len > MAX_DH_KEY_LEN) {
        fprintf(stderr, "public key length is not supported\n");
        return 0;
    }
    if (!file) {
        printf("\033[31m[X] Error loading public key\033[0m\n");
        return 0;
    }
    while ((ch = getc(file)) != EOF) {
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+') {
            digit = 62;
        } else if (ch == '/') {
            digit = 63;
        } else if (ch == '=') {
            break;
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            fclose(file);
            printf("Invalid character in public key file : %s\n", content);
            return 0;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4) {
            if ((len - posn) < 3) {
                fclose(file);
                printf("Public key value is too long\n");
                return 0;
            }
            group_size = 0;
            key[posn++] = (uint8_t)(group >> 16);
            key[posn++] = (uint8_t)(group >> 8);
            key[posn++] = (uint8_t)group;
        }
    }
    if (group_size == 3) {
        if ((len - posn) < 2) {
            fclose(file);
            printf("Public key value is too long\n");
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 10);
        key[posn++] = (uint8_t)(group >> 2);
    } else if (group_size == 2) {
        if ((len - posn) < 1) {
            fclose(file);
            printf("Public key value is too long\n");
            return 0;
        }
        key[posn++] = (uint8_t)(group >> 4);
    }
    if (posn < len) {
        fclose(file);
        printf("Public key value is too short\n");
        return 0;
    }
    fclose(file);
    return 1;
}

/* Connects to a remote echo server.  Returns the file descriptor or -1
   if an error occurs while creating the socket or trying to connect. */
int jossnet_connect(const char *hostname, int port)
{
    struct addrinfo hints;
    struct addrinfo *result = 0;
    struct addrinfo *current;
    int fd, err;
    sockopt_type opt;
    char service[64];

    /* Look up the address of the remote party */
    snprintf(service, sizeof(service), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(hostname, service, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(err));
        return -1;
    }

    /* Try each of the return addresses in turn until one connects */
    for (current = result; current != 0; current = current->ai_next) {
        /* Create the socket and set some useful options on it */
        fd = socket(current->ai_family, current->ai_socktype,
                    current->ai_protocol);
        if (fd < 0)
            continue;
        opt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *)&opt, sizeof(opt)) < 0) {
            perror("setsockopt TCP_NODELAY");
            closesocket(fd);
            freeaddrinfo(result);
            return -1;
        }

        /* Attempt to connect to the remote party using this address */
        if (connect(fd, current->ai_addr, current->ai_addrlen) < 0) {
            perror("connect");
            closesocket(fd);
            continue;
        }

        /* We are connected */
        freeaddrinfo(result);
        return fd;
    }

    /* If we get here, then none of the returned addresses worked */
    fprintf(stderr, "%s: Could not connect\n", hostname);
    freeaddrinfo(result);
    return -1;
}

#if !(defined(__WIN32__) || defined(WIN32))

static void sigchld_handler(int sig)
{
    /* Nothing to do here */
}

#endif

/* Maximum number of addresses we can listen on */
#define MAX_LISTEN 4

/* Accepts an incoming connection from an JOSSNET client.  Returns the file
   descriptor of the socket to use to communicate with the client.

   Internally this function will fork the process and return the file
   descriptor for the connection in the child.  The parent process will
   never return from this function. */
int jossnet_accept(int port)
{
    struct addrinfo hints;
    struct addrinfo *result = 0;
    struct addrinfo *current;
#if HAVE_POLL
    struct pollfd poll_fd[MAX_LISTEN];
#endif
    int listen_fd[MAX_LISTEN];
    int num_listen = 0;
    int fd, accept_fd;
    int err, index;
    sockopt_type opt;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    char service[64];
    int seenIPV4 = 0;

#if !(defined(__WIN32__) || defined(WIN32))
    /* We will need SIGCHLD signals to clean up child processes */
    signal(SIGCHLD, sigchld_handler);
#endif

    /* Ask getaddrinfo() for a list of socket addresses to bind to */
    snprintf(service, sizeof(service), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    err = getaddrinfo(NULL, service, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "Could not find an address to bind to: %s\n",
                gai_strerror(err));
        exit(1);
    }

    /* Bind to all addresses we can */
    memset(listen_fd, 0, sizeof(listen_fd));
    for (current = result; current != 0 && num_listen < MAX_LISTEN;
            current = current->ai_next) {
        fd = socket(current->ai_family, current->ai_socktype,
                    current->ai_protocol);
        if (fd < 0)
            continue;
        opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       (const void *)&opt, sizeof(opt)) < 0) {
            perror("setsockopt SO_REUSEADDR");
            closesocket(fd);
            exit(1);
        }
        if (current->ai_family == AF_INET)
            seenIPV4 = 1;
#if defined(IPV6_V6ONLY) && defined(IPPROTO_IPV6)
        if (current->ai_family == AF_INET6 && seenIPV4) {
            /* We're trying to bind to both IPv4 and IPv6.
               Set the IPv6-only option or the second bind
               attempt may fail.  If the option doesn't work,
               then let the second bind fail below anyway. */
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                       (const void *)&opt, sizeof(opt));
        }
#endif
        if (bind(fd, current->ai_addr, current->ai_addrlen) < 0) {
            perror("bind");
            closesocket(fd);
            continue;
        }
        if (listen(fd, 5) < 0) {
            closesocket(fd);
            continue;
        }
        listen_fd[num_listen] = fd;
#if HAVE_POLL
        poll_fd[num_listen].fd = fd;
        poll_fd[num_listen].events = POLLIN;
        poll_fd[num_listen].revents = 0;
#endif
        ++num_listen;
    }
    freeaddrinfo(result);

    /* If we couldn't bind to anything, then fail */
    if (!num_listen) {
        fprintf(stderr, "Could not bind to the specified port on any address\n");
        exit(1);
    }

    /* Loop forever waiting for incoming connections */
    accept_fd = -1;
    for (;;) {
        /* Wait for one of the descriptors to be ready to accept() */
#if HAVE_POLL
        for (index = 0; index < num_listen; ++index)
            poll_fd[index].revents = 0;
        err = poll(poll_fd, num_listen, -1);
        if (err < 0) {
            if (errno == EINTR) {
                /* Interrupted by a system call.  This is probably due to a
                   child process terminating.  Clean up any waiting children. */
                int status;
                while (waitpid(-1, &status, WNOHANG) >= 0)
                    ;   /* Do nothing */
                continue;
            }
            perror("poll");
            exit(1);
        }
        fd = -1;
        for (index = 0; index < num_listen; ++index) {
            if (poll_fd[index].revents != 0) {
                fd = listen_fd[index];
                break;
            }
        }
        if (fd == -1)
            continue;
#else
        fd_set read_set;
        int nfds = 0;
        FD_ZERO(&read_set);
        for (index = 0; index < num_listen; ++index) {
            FD_SET(listen_fd[index], &read_set);
            if (listen_fd[index] >= nfds)
                nfds = listen_fd[index] + 1;
        }
        err = select(nfds, &read_set, NULL, NULL, NULL);
        if (err <= 0)
            continue;
        fd = -1;
        for (index = 0; index < num_listen; ++index) {
            if (FD_ISSET(listen_fd[index], &read_set)) {
                fd = listen_fd[index];
                break;
            }
        }
        if (fd == -1)
            continue;
#endif

        /* Accept the incoming connection */
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        accept_fd = accept(fd, (struct sockaddr *)&addr, &addrlen);
#if defined(__WIN32__) || defined(WIN32)
        if (accept_fd >= 0) {
            /* Win32 doesn't have a direct equivalent to fork so merely
               close the listening sockets and return.  This means that
               the server can only handle a single connection on Win32.
               Fix this later by using threads to handle clients instead. */
            for (index = 0; index < num_listen; ++index)
                closesocket(listen_fd[index]);
            break;
        }
#else
        if (accept_fd >= 0) {
            /* Fork and return the new socket in the child */
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                closesocket(accept_fd);
                for (index = 0; index < num_listen; ++index)
                    closesocket(listen_fd[index]);
                exit(1);
            } else if (pid == 0) {
                /* In the child process */
                for (index = 0; index < num_listen; ++index)
                    closesocket(listen_fd[index]);
                break;
            } else {
                /* In the parent process */
                closesocket(accept_fd);
            }
        } else if (errno == EINTR) {
            /* Interrupted by a system call.  This is probably due to a
               child process terminating.  Clean up any waiting children. */
            int status;
            while (waitpid(-1, &status, WNOHANG) >= 0)
                ;   /* Do nothing */
        } else {
            perror("accept");
            for (index = 0; index < num_listen; ++index)
                closesocket(listen_fd[index]);
            exit(1);
        }
#endif
    }

    /* Add some useful options to the incoming socket and then return */
    opt = 1;
    if (setsockopt(accept_fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt TCP_NODELAY");
        closesocket(accept_fd);
        exit(1);
    }
    return accept_fd;
}

static void jossnet_print_packet(const char *tag, const uint8_t *packet, size_t len)
{
    size_t index;
    printf("%s:", tag);
    for (index = 0; index < len; ++index) {
        printf(" %02x", packet[index]);
        if ((index % 16) == 15 && index != (len - 1))
            printf("\n   ");
    }
    printf("\n");
}

/* Receives an exact number of bytes, blocking until they are all available.
   Returns non-zero if OK, zero if the connection has been lost. */
static int jossnet_recv_exact_internal(int fd, uint8_t *packet, size_t len)
{
    size_t received = 0;
    while (len > 0) {
        int size = recv(fd, (void *)packet, len, 0);
        if (size < 0) {
#if defined(__WIN32__) || defined(WIN32)
            return 0;
#else
            if (errno == EINTR || errno == EAGAIN)
                continue;
            perror("recv");
            return 0;
#endif
        } else if (size == 0) {
            return 0;
        } else {
            packet += size;
            len -= size;
            received += size;
        }
    }
    return received;
}

/* Receives an exact number of bytes, blocking until they are all available.
   Returns non-zero if OK, zero if the connection has been lost. */
int jossnet_recv_exact(int fd, uint8_t *packet, size_t len)
{
    size_t received = jossnet_recv_exact_internal(fd, packet, len);
    if (received) {
        if (jossnet_verbose)
            jossnet_print_packet("Rx", packet, received);
    } else if (jossnet_verbose) {
        printf("Rx: EOF\n");
    }
    return received;
}

/* Receives a complete Noise packet, including the two-byte length prefix.
   Returns the length of the packet, zero if the connection has been lost
   or the packet is too large for the supplied buffer. */
size_t jossnet_recv(int fd, uint8_t *packet, size_t max_len)
{
    size_t size;
    if (max_len < 2)
        return 0;
    if (!jossnet_recv_exact_internal(fd, packet, 2))
        return 0;
    size = (((size_t)(packet[0])) << 8) | ((size_t)(packet[1]));
    if (size > (max_len - 2))
        return 0;
    size = jossnet_recv_exact_internal(fd, packet + 2, size);
    if (size)
        size += 2;
    if (jossnet_verbose)
        jossnet_print_packet("Rx", packet, size);
    return size;
}

/* Sends a complete Noise packet, including the two-byte length prefix.
   Returns non-zero if OK, zero if the connection has been lost. */
int jossnet_send(int fd, const uint8_t *packet, size_t len)
{
    int size;
    if (jossnet_verbose)
        jossnet_print_packet("Tx", packet, len);
    while ((size = send(fd, (const void *)packet, len, MSG_NOSIGNAL)) != (int)len) {
        if (size < 0) {
#if defined(__WIN32__) || defined(WIN32)
            return 0;
#else
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
                return 0;
            } else {
                perror("send");
                return 0;
            }
#endif
        } else {
            packet += size;
            len -= size;
        }
    }
    return 1;
}

/* Closes a socket */
void jossnet_close(int fd)
{
    closesocket(fd);
}
