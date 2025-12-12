#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<openssl/sha.h>

int main(int argc, char *argv[]){
    const char *message = argv[1];
    unsigned char res[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)message, strlen(message), res);
    printf("SHA256 Hash: ");
    for(int i=0; i<SHA256_DIGEST_LENGTH; i++){
        printf("%02x", res[i]);
    }
    printf("\n");
    return 0;
}