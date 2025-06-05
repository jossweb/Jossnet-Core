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
#include "../server/common.h"
#include "../keygen/keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "../cjson/cJSON.h"

/* Parsed command-line options */
static const int dh = 25519;
static char *client_private_key = "keys/client_key_25519";
static char *server_public_key = "keys/server_key_25519.pub";
static const char *psk_file = "keys/psk";
static uint8_t psk[32];
static char *protocol = "NoisePSK_KK_25519_ChaChaPoly_BLAKE2b";
static const char *hostname = "localhost";
static int port = 2006;
static int padding = 0;
static int fixed_ephemeral = 0;

const KeyFile key_files[] = {
    {"25519", "keys/client_key_25519", "keys/client_key_25519.pub"},
    {"448",   "keys/client_key_448",   "keys/client_key_448.pub"}
};

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message[MAX_MESSAGE_LEN + 2];


static void save_data_from_server(char* json){
	cJSON *root = cJSON_Parse((char*)json);
	if(root){
		cJSON *success = cJSON_GetObjectItemCaseSensitive(root, "success");
		if(success){
			cJSON *serverkey = cJSON_GetObjectItemCaseSensitive(root, "server_key");
 			char* path;
			if(dh==25519){
				path="keys/server_key_25519.pub";
			}else{
				path="keys/server_key_448.pub";
			}
			write_in_file(path, (char*)serverkey);
		}else{
			printf("Server don't send data successfully\n");
		}
	}else{
		printf("Failed to parse JSON from server\n");
	}
	printf("Data saved successfully\n");
}
/* Initialize the handshake using command-line options */
static int initialize_handshake(NoiseHandshakeState *handshake, const void *prologue, size_t prologue_len){
    NoiseDHState *dh;
    uint8_t *key = 0;
    size_t key_len = 0;
    int err;
    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return 0;
    }
    if (psk_file && noise_handshakestate_needs_pre_shared_key(handshake)) {
        if (!jossnet_load_public_key(psk_file, psk, sizeof(psk), 1)){
			noise_perror("psk", err);
			return 0;
		}
        err = noise_handshakestate_set_pre_shared_key
            (handshake, psk, sizeof(psk));
        if (err != NOISE_ERROR_NONE) {
            noise_perror("psk", err);
            return 0;
        }
    }
    /* Set the local keypair for the client */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        if (client_private_key) {
            dh = noise_handshakestate_get_local_keypair_dh(handshake);
            key_len = noise_dhstate_get_private_key_length(dh);
            key = (uint8_t *)malloc(key_len);
            if (!key)
                return 0;
            if (!jossnet_load_private_key(client_private_key, key, key_len)) {
                noise_free(key, key_len);
                return 0;
            }
            err = noise_dhstate_set_keypair_private(dh, key, key_len);
            noise_free(key, key_len);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("set client private key", err);
                return 0;
            }
        } else {
            fprintf(stderr, "Client private key required, but not provided.\n");
            return 0;
        }
    }

    /* Set the remote public key for the server */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        if (server_public_key) {
            dh = noise_handshakestate_get_remote_public_key_dh(handshake);
            key_len = noise_dhstate_get_public_key_length(dh);
            key = (uint8_t *)malloc(key_len);
            if (!key)
                return 0;
            if (!jossnet_load_public_key(server_public_key, key, key_len, 1)) {
                noise_free(key, key_len);
                return 0;
            }
            err = noise_dhstate_set_public_key(dh, key, key_len);
            noise_free(key, key_len);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("set server public key", err);
                return 0;
            }
        } else {
            fprintf(stderr, "Server public key required, but not provided.\n");
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[])
{
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    JossnetProtocolId id;
    int err, ok;
    int action;
    int fd;
    size_t message_size;
    size_t max_line_len;

	if (!(argc > 1 && !strcmp(argv[1], "--initkeys"))) {
		if ((dh == 25519) &&
    	(access("keys/server_key_25519.pub", R_OK) ||
   		access(key_files[0].private_key, R_OK) ||
   		access(key_files[0].public_key, R_OK))) {
   			int status = system("./client --initkeys");
   			if (status != 0) {
       			fprintf(stderr, "Error --initkeys\n");
    	 		exit(1);
    		}
		}

		if ((dh == 448) &&
    		(access("keys/server_key_448.pub", R_OK) ||
     		access(key_files[1].private_key, R_OK) ||
     		access(key_files[1].public_key, R_OK))) {

    		int status = system("./client --initkeys");
    		if (status != 0) {
        		fprintf(stderr, "Error --initkeys\n");
       	 		exit(1);
    		}
		}
	}

	if (argc > 1 && !strcmp(argv[1], "--initkeys")) {
        printf("[!] Init keys mode is enable\n");
		if(dh==448){
			protocol = "Noise_NN_448_ChaChaPoly_BLAKE2b";
			client_private_key = "keys/client_key_448";
		}else if(dh==25519){
			protocol = "Noise_NN_448_ChaChaPoly_BLAKE2b";
			client_private_key = "keys/client_key_25519";
		}else{
			printf("[X] Init keys mode is disabled\n %d is not supported\n", dh);
			return 0;
		}
		server_public_key = NULL;

		//generate new keys
		int error = 0;
		for (int i = 0; i < 2; i++) {
        	error = gen_keys(key_files[i]);
    	}
		if (error) {
        	printf("\033[31m[X] Error : can't generate keys\033[0m\n");
        	return 1;
    	} else {
        	printf("\033[0;32m[✓] Success: Keys and PSK generated successfully\033[0m\n");
    	}
    }else if(dh==448){
		client_private_key = "client_key_448";
		server_public_key = "server_key_448.pub";
		protocol = "NoisePSK_KK_448_ChaChaPoly_BLAKE2b";
	}
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Check that the echo protocol supports the handshake protocol.
       One-way handshake patterns and XXfallback are not yet supported. */
    if (!jossnet_get_protocol_id(&id, protocol)) {
        fprintf(stderr, "%s: not supported by the echo protocol\n", protocol);
        return 1;
    }

    /* Create a HandshakeState object for the protocol */
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    /* Set the handshake options and verify that everything we need
       has been supplied on the command-line. */
    if (!initialize_handshake(handshake, &id, sizeof(id))) {
        noise_handshakestate_free(handshake);
        return 1;
    }
    /* Attempt to connect to the remote party */
    fd = jossnet_connect(hostname, port);
    if (fd < 0) {
        noise_handshakestate_free(handshake);
		printf("Can't find the server, check host and port\n");
        return 1;
    }
    /* Send the jossnet protocol identifier to the server */
    ok = 1;
    if (!jossnet_send(fd, (const uint8_t *)&id, sizeof(id)))
        ok = 0;

    /* Start the handshake */
    if (ok) {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }

    /* Run the handshake until we run out of things to read or write */
    while (ok) {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            message[0] = (uint8_t)(mbuf.size >> 8);
            message[1] = (uint8_t)mbuf.size;
            if (!jossnet_send(fd, message, mbuf.size + 2)) {
                ok = 0;
                break;
            }
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            /* Read the next handshake message and discard the payload */
            message_size = jossnet_recv(fd, message, sizeof(message));
            if (!message_size) {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        } else {
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    /* If the action is not "split", then the handshake has failed */
    if (ok && noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }

    /* Split out the two CipherState objects for send and receive */
    if (ok) {
        err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }

    /* We no longer need the HandshakeState */
    noise_handshakestate_free(handshake);
    handshake = 0;

    /* If we will be padding messages, we will need a random number generator */
    if (ok && padding) {
        err = noise_randstate_new(&rand);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("random number generator", err);
            ok = 0;
        }
    }

    /* Tell the user that the handshake has been successful */
    if (ok) {
        printf("%s handshake complete. Send a message to the server\n", protocol);
    }
	//get client's public key
	char* pub_key;
	if(dh==448){
		pub_key = read_file("keys/client_key_448.pub");
	}else if(dh==25519){
		pub_key = read_file("keys/client_key_448.pub");
	}
	if(!pub_key){
		return 1;
	}
	int sent_init_request = 0;
    /* Read lines from stdin, send to the server, and wait for server's response */
    max_line_len = sizeof(message) - 2 - noise_cipherstate_get_mac_length(send_cipher);
    while (ok) {
        /* Pad the message to a uniform size */
		if (argc > 1 && !strcmp(argv[1], "--initkeys") && !sent_init_request) {
        	cJSON *response = cJSON_CreateObject();
        	cJSON_AddStringToObject(response, "endpoint", "registre");
        	cJSON_AddNumberToObject(response, "type", dh);
        	cJSON_AddStringToObject(response, "key", pub_key);
        	char* json_str = cJSON_PrintUnformatted(response);
        	size_t len = strlen(json_str);

        	if (len >= max_line_len) {
            	fprintf(stderr, "Requête JSON trop longue\n");
            	free(json_str);
            	cJSON_Delete(response);
            	ok = 0;
            	break;
        	}
        	memcpy(message + 2, json_str, len + 1);
        	message_size = len;
        	free(json_str);
        	cJSON_Delete(response);
        	sent_init_request = 1;
    	}else{
			if(!fgets((char *)(message + 2), max_line_len, stdin)){
				break;
			}
		}
        message_size = strlen((const char *)(message + 2));
        if (padding) {
            err = noise_randstate_pad
                (rand, message + 2, message_size, max_line_len,
                 NOISE_PADDING_RANDOM);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("pad", err);
                ok = 0;
                break;
            }
            message_size = max_line_len;
        }

        /* Encrypt the message and send it */
        noise_buffer_set_inout(mbuf, message + 2, message_size, sizeof(message) - 2);
        err = noise_cipherstate_encrypt(send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("write", err);
            ok = 0;
            break;
        }
        message[0] = (uint8_t)(mbuf.size >> 8);
        message[1] = (uint8_t)mbuf.size;
        if (!jossnet_send(fd, message, mbuf.size + 2)) {
            ok = 0;
            break;
        }

        /* Wait for a message from the server */
        message_size = jossnet_recv(fd, message, sizeof(message));
        if (!message_size) {
            fprintf(stderr, "Remote side terminated the connection\n");
            ok = 0;
            break;
        }

        /* Decrypt the incoming message */
        noise_buffer_set_input(mbuf, message + 2, message_size - 2);
        err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Remove padding from the message if necessary */
        if (padding) {
            /* Find the first '\n' and strip everything after it */
            const uint8_t *end = (const uint8_t *)
                memchr(mbuf.data, '\n', mbuf.size);
            if (end)
                mbuf.size = end + 1 - mbuf.data;
        }

        /* Write the server's response in standard output */
        fputs("Received: ", stdout);
        fwrite(mbuf.data, 1, mbuf.size, stdout);

		if(argc > 1 && !strcmp(argv[1], "--initkeys")){
			save_data_from_server((char *)mbuf.data);
			break;
		}
    }

    /* Clean up and exit */
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    noise_randstate_free(rand);
    jossnet_close(fd);
    return ok ? 0 : 1;
}
