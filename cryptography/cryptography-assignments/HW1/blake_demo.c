#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/evp.h>

int main(int argc, char* argv[]){
    const char* message = argv[1];
    // assign allocated space to store the result
    unsigned char* hashResult = malloc(EVP_MAX_MD_SIZE);
    unsigned int hashlen =0;
    // define the context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    // lookup the digest algorithm by name (openssl list --digest-algorithms)
    const EVP_MD *md = EVP_get_digestbyname("BLAKE2s256");
    // initialize
    EVP_DigestInit_ex(mdctx, md, NULL);
    // update
    EVP_DigestUpdate(mdctx, message, strlen(message));
    // finalize
    EVP_DigestFinal_ex(mdctx, hashResult, &hashlen);
    printf("Message: %s", message);
    printf("\n");
    printf("Hash: ");
    for(int i =0; i< hashlen; i++){
        printf("%02x", hashResult[i]);
    }
    printf("\n");
    // free the buffer :)
    free(hashResult);
    return 0;
}