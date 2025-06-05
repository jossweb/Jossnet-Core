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
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "../keygen/keygen.h"
#include "../cjson/cJSON.h"
#include "endpoint.h"

/* Parsed command-line options */
static const char *key_dir = "keys/";
static int port = 2006; //Change port

/* Loaded keys */
#define CURVE25519_KEY_LEN 32
#define CURVE448_KEY_LEN 56
static uint8_t client_key_25519[CURVE25519_KEY_LEN];
static uint8_t server_key_25519[CURVE25519_KEY_LEN];
static uint8_t client_key_448[CURVE448_KEY_LEN];
static uint8_t server_key_448[CURVE448_KEY_LEN];

static uint8_t psk[32];

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 65535
static uint8_t message[MAX_MESSAGE_LEN + 2];

const KeyFile key_files[] = {
    {"25519", "server_key_25519", "server_key_25519.pub"},
    {"448",   "server_key_448",   "server_key_448.pub"}
};

static char* register_newuser(char *message) {
    int success = 1;
    char* content = "Key successfully registered, you can now interact with the server without using the XX mod, see the documentation";
    cJSON *root = cJSON_Parse((char*)message);
    if (root) {
        cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(root, "endpoint");
        cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
        cJSON *key = cJSON_GetObjectItemCaseSensitive(root, "key");
        if (endpoint && type && key && cJSON_IsNumber(type) && cJSON_IsString(key)) {
			if(!strcmp(endpoint->valuestring, "registre")){
				int type_val = type->valueint;
            	const char *key_str = key->valuestring;
            	if (type_val == 25519) {
                	if (jossnet_load_public_key(key_str, server_key_25519, sizeof(server_key_25519), 0)) {
                    	FILE *f = fopen("clients-25519.txt", "a");
                    	if (f == NULL) {
                        	printf("[X] Error can't open file keys/clients25519.json");
                    	} else {
                        	fprintf(f, "%s\n", key_str);
                        	fclose(f);
                    	}
                	} else {
                    	success = 0;
                    	content = "Can't register your key";
                	}
            	} else if (type_val == 448) {
                	if (jossnet_load_public_key(key_str, server_key_448, sizeof(server_key_448), 0)) {
                    	FILE *f = fopen("clients-448.txt", "a");
						if (f == NULL) {
    						printf("[X] Error can't open file clients.txt\n");
						} else {
    						fprintf(f, "%s\n", key_str);
    						fclose(f);
						}
                	} else {
                    	success = 0;
                    	content = "Can't register your key";
                	}
            	} else {
                	success = 0;
                	content = "Bad type, check the documentation";
            	}
			}else{
				success = 0;
            	content = "Bad request 1";
			}
        } else {
            success = 0;
            content = "Bad request 2";
        }
        cJSON_Delete(root);
    } else {
        success = 0;
        content = "Bad request";
    }
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "success", success);
    cJSON_AddStringToObject(response, "response", content);
    char *out = cJSON_Print(response);
    cJSON_Delete(response);
    return out;
}

static char* set_return_message(char *message){
    char* response;
    cJSON *root = cJSON_Parse((char*)message);
    if(root){
        cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(root, "endpoint");
        cJSON *content_request = cJSON_GetObjectItemCaseSensitive(root, "content");
        if (cJSON_IsString(endpoint) && (endpoint->valuestring != NULL)) {
            int success = 1;
            char* content;
            if (!strcmp(endpoint->valuestring, "echo")) {
                content = ep_echo(content_request->valuestring);
            } else {
                content = ep_error();
                success = 0;
            }
            cJSON *root = cJSON_CreateObject();
            cJSON_AddNumberToObject(root, "success", success);
            cJSON_AddStringToObject(root, "response", content);
            response = cJSON_Print(root);
            //free(content);
        }
        cJSON_Delete(root);
    }else{
        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "success", 0);
        cJSON_AddStringToObject(root, "response", "Error : bad request");
        response = cJSON_Print(root);
        cJSON_Delete(root);
    }
    return response;
}
/* Initializes the handshake with all necessary keys */
static int initialize_handshake
    (NoiseHandshakeState *handshake, const NoiseProtocolId *nid,
     const void *prologue, size_t prologue_len)
{
    NoiseDHState *dh;
    int dh_id;
    int err;

    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return 0;
    }

    /* Set the PSK if one is needed */
    if (nid->prefix_id == NOISE_PREFIX_PSK) {
        err = noise_handshakestate_set_pre_shared_key
            (handshake, psk, sizeof(psk));
        if (err != NOISE_ERROR_NONE) {
            noise_perror("psk", err);
            return 0;
        }
    }

    /* Set the local keypair for the server based on the DH algorithm */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_keypair_private(dh, server_key_25519, sizeof(server_key_25519));
        } else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_keypair_private(dh, server_key_448, sizeof(server_key_448));
        } else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set server private key", err);
            return 0;
        }
    }

    /* Set the remote public key for the client */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_public_key(dh, client_key_25519, sizeof(client_key_25519));
        } else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_public_key(dh, client_key_448, sizeof(client_key_448));
        } else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set client public key", err);
            return 0;
        }
    }
    /* Ready to go */
    return 1;
}

int main(int argc, char *argv[])
{
    NoiseHandshakeState *handshake = 0;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    JossnetProtocolId id;
    NoiseProtocolId nid;
    NoiseBuffer mbuf;
    size_t message_size;
    int fd;
    int err;
    int ok = 1;
    int action;

    if (chdir(key_dir) < 0) {
        perror(key_dir);
        return 1;
    }
    /*Gen keys and psk
    int error;
    for(int i=0; i<2; i++) {
		printf("%d", i);
        error = gen_keys(key_files[i]);
    }
    if(error){
        printf("\033[31m[X] Error : can't generate keys\n\033[31m");
        return 1;
    }else{
        printf("\033[0;32m[✓] Success: Keys and PSK generated successfully\033[0m\n");
    }*/
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }
    if (!jossnet_load_private_key("server_key_25519", server_key_25519, sizeof(server_key_25519))) {
        return 1;
    }
    if (!jossnet_load_private_key("server_key_448", server_key_448, sizeof(server_key_448))) {
        return 1;
    }
    if (!jossnet_load_public_key("psk", psk, sizeof(psk), 1)) {
        return 1;
    }
	if (!jossnet_load_public_key("8RmZ3dtdeQHXjtcW40fdAGM/HjDTeuKedBh0Bbeq1zo=", client_key_25519, sizeof(client_key_25519), 0)) {
		printf("jossnet_load_public_key failed\n");
		return 1;
	}
	//Add public key of verified clients
	char line[256];
	FILE *f = fopen("clients-25519.txt", "r");
	if (f == NULL) {
    	printf("Cannot open file\n");
	}else{
		if (fgets(line, sizeof(line), f)) {
    		line[strcspn(line, "\n")] = '\0';
    		printf("Clé : %s\n", line);
    		if (!jossnet_load_public_key(line, client_key_25519, sizeof(client_key_25519), 0)) {
        		printf("can't add client's key : %s", line);
        		return 1;
    		} else {
        	printf("%s : added successfully\n", line);
			}
    	}
	}
	f = fopen("clients-448.txt", "r");
	if (f == NULL) {
    	printf("Cannot open file\n");
	}else{
		while (fgets(line, sizeof(line), f)) {
    		line[strcspn(line, "\n")] = '\0';
    		printf("Clé : %s\n", line);
			if (!jossnet_load_public_key(line, server_key_448, sizeof(server_key_448), 0)) {
				printf("can't add client's key : %s", line);
				return 1;
			}else{
				printf("%s : added successfully\n", line);
			}
		}
	}
	fclose(f);
    /* Accept an incoming connection */
    fd = jossnet_accept(port);
    /* Read the echo protocol identifier sent by the client */
    if (ok && !jossnet_recv_exact(fd, (uint8_t *)&id, sizeof(id))) {
        fprintf(stderr, "Did not receive the jossnet protocol identifier\n");
        ok = 0;
    }
    /* Convert the echo protocol identifier into a Noise protocol identifier */
    if (ok && !jossnet_to_noise_protocol_id(&nid, &id)) {
        fprintf(stderr, "Unknown jossnet protocol identifier\n");
        ok = 0;
    }
    /* Create a HandshakeState object to manage the server's handshake */
    if (ok) {
        err = noise_handshakestate_new_by_id
            (&handshake, &nid, NOISE_ROLE_RESPONDER);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("create handshake", err);
            ok = 0;
        }
    }
    /* Set all keys that are needed by the client's requested jossnet protocol */
    if (ok) {
        if (!initialize_handshake(handshake, &nid, &id, sizeof(id))) {
            ok = 0;
        }
    }
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
	//check protocole client
	NoiseProtocolId proto_id;
	char proto_name[NOISE_MAX_PROTOCOL_NAME + 1];
	int is_nn = 0;

	// check id noise protocol
	noise_handshakestate_get_protocol_id(handshake, &proto_id);
	// get protocol name
	noise_protocol_id_to_name(proto_name, sizeof(proto_name), &proto_id);

	// On vérifie si le nom commence par "Noise_XX_"
	printf("\n --Protocol ID: %s--\n", proto_name);
	if (strncmp(proto_name, "Noise_NN_", 9) == 0) {
    	is_nn = 1;
	}

	// free handshake
	noise_handshakestate_free(handshake);
	handshake = 0;

    if (ok && is_nn) {
		//if nn we autorize only 1 request (to register client's public key)
        printf("[!] Request from unknown client !\n");
        message_size = jossnet_recv(fd, message, sizeof(message));
        if (message_size) {
            noise_buffer_set_inout(mbuf, message + 2, message_size - 2, sizeof(message) - 2);
            err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
            if (err == NOISE_ERROR_NONE) {
                char* response = register_newuser((char*)mbuf.data);
                size_t response_len = strlen(response);
                if (response_len <= mbuf.max_size) {
                    memcpy(mbuf.data, response, response_len);
                    mbuf.size = response_len;
                } else {
                    mbuf.size = 0;
                }
                err = noise_cipherstate_encrypt(send_cipher, &mbuf);
                if (err == NOISE_ERROR_NONE) {
                    message[0] = (uint8_t)(mbuf.size >> 8);
                    message[1] = (uint8_t)mbuf.size;
                    jossnet_send(fd, message, mbuf.size + 2);
                }
            }
        }
    } else {
        //other mod
        while (ok) {
            message_size = jossnet_recv(fd, message, sizeof(message));
            if (!message_size)
                break;
            noise_buffer_set_inout(mbuf, message + 2, message_size - 2, sizeof(message) - 2);
            err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read", err);
                ok = 0;
                break;
            }
            printf("message (dechiffré, texte): %s\n",(char*)mbuf.data);
            char* response = set_return_message((char*)mbuf.data);

            size_t response_len = strlen(response);
            if (response_len <= mbuf.max_size) {
                memcpy(mbuf.data, response, response_len);
                mbuf.size = response_len;
            } else {
                mbuf.size = 0;
            }
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
        }
    }
    /* Clean up and exit*/
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    jossnet_close(fd);
    return ok ? 0 : 1;
}
