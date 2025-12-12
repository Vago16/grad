#include<stdio.h>
#include<string.h>
// openssl imports
#include<openssl/hmac.h>
#include<openssl/sha.h>
#include<openssl/evp.h>

#define DIGEST_LENGTH SHA256_DIGEST_LENGTH

int main(int argc, char *argv[]){
    char *key = argv[1];
    char *message = argv[2];
    // create a storage space to store the hash and the result of HMAC
    unsigned char r[DIGEST_LENGTH];
    unsigned char res[EVP_MAX_MD_SIZE];
    unsigned int res_len=0;
    // hash the key and convert the key to hex
    // set the hash length to be digest length*2 +1 and the last char should be \0
    SHA256((const unsigned char*)key, strlen(key), r);
    
    // call the hmac function
    HMAC(EVP_sha256(), r, DIGEST_LENGTH, (unsigned char*) message, strlen(message), res, &res_len);
    
    // display key in hex, message and , and hmac
    printf("Key: ");
    for(int i=0; i<DIGEST_LENGTH; i++){
      printf("%02x", r[i]);  
    }
    printf("\n");

    printf("Message: ");
    for(int i=0; i<strlen(message); i++){
      printf("%c", message[i]);  
    }
    printf("\n");

    printf("HMAC: ");
    for(int i=0; i<EVP_MAX_MD_SIZE; i++){
      printf("%02x", res[i]); 
    }
    printf("\n");

    return 0;
}
