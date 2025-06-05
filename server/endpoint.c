/*
 * Modified and adapted for the Jossnet project
 * © 2025 FIGUEIRAS Jossua – Licensed under the MIT License.
 */

#include "endpoint.h"

char* ep_echo(char* content){
    return content;
}
char* ep_error(){
    return "Error: Endpoint not found";
}
