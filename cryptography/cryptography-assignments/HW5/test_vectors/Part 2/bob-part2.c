#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <ctype.h> 
#include <openssl/evp.h>
#include <openssl/sha.h>

//helper function prototypes
char* Read_File(const char *filename, long *fileLen);
int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len);
void Convert_to_Hex(char *output, const uint8_t *input, size_t len);
void Write_File(const char *filename, const char *content);
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len);
void XOR_Bytes(uint8_t *output, const uint8_t *b1, const uint8_t *b2, size_t len);
int Compute_SHA256(const uint8_t *data, size_t data_len, uint8_t *hash_output);

int main (int argc, char *argv[]) {

    //if number of commands is not correct, exit program
    if (argc != 4) {
        printf("Must put in k1_ab.txt, alice_kyber_public.txt, and bob_dilithium_private.txt as command line arguments.\n");
        return 1;
    }

    //initialize command line arguments
    const char *bob_sk_file   = argv[1];
    const char *alice_pk_file = argv[2];
    const char *k1_file       = argv[3];

    //liboqs functions
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);      // Constructs an OQS_KEM object for a particular algorithm
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);        //// Constructs an OQS_SIG object for a particular algorithm

    //1. Bob reads K1 from file: k1_ab.txt
    long k1_len;        //variable to store length of string in text for reading
    char *k1_hex = Read_File(k1_file, &k1_len);

    //2. Bob reads Alice’s Kyber public key (alice kyber public.txt) from file
    long alice_pk_len;      //variable to store length of string in text for reading
    char *alice_pk_hex = Read_File(alice_pk_file, &alice_pk_len);
    uint8_t *alice_pk = malloc(kem->length_public_key);     //variable to store bytes after converted from hex
    Convert_from_Hex(alice_pk, alice_pk_hex, kem->length_public_key);
    
    //3. Bob reads his Dilithium private key (bob dilithium private.txt) from file
    long bob_sk_len;        //variable to store length of string in text for reading
    char *bob_sk_hex = Read_File(bob_sk_file, &bob_sk_len);
    uint8_t *bob_sk = malloc(sig->length_secret_key);       //variable to store bytes after converted from hex
    Convert_from_Hex(bob_sk, bob_sk_hex, sig->length_secret_key);

    //verify that the length of the data read matches the expected key lengths defined by liboqs
    if (alice_pk_len / 2 != kem->length_public_key) {
        printf("Error: Alice Kyber public key did not match.\n");
        return 1;
    }
    if (bob_sk_len / 2 != sig->length_secret_key) {
        printf("Error: Bob Dilithium private key did not match.\n");
        return 1;
    }

    //4. Using Alice’s Kyber public key, Bob preforms key encapsulation
    uint8_t *k2_bob = malloc(kem->length_shared_secret);        //shared secret
    uint8_t *ct_bob = malloc(kem->length_ciphertext);       //ciphertext
    OQS_KEM_encaps(kem, ct_bob, k2_bob, alice_pk);      // Key encapsulation algorithm

    //5. After generating the shared secret (K2B ) and ciphertext (CTB ), Bob will use his Dilithium private key to sign the ciphertext
    uint8_t *sig_bob = malloc(sig->length_signature);
    size_t sig_bob_len = 0;
    OQS_SIG_sign(sig, sig_bob, &sig_bob_len, ct_bob, kem->length_ciphertext, bob_sk);       // Signature generation algorithm

    //6. Compute the final shared key as: H(K1 ⊕ K2) and write to bob_final_key.txt
    uint8_t *k1_bytes = malloc(kem->length_shared_secret);
    Convert_from_Hex(k1_bytes, k1_hex, kem->length_shared_secret);

    uint8_t *xor_result = malloc(kem->length_shared_secret);
    XOR_Bytes(xor_result, k1_bytes, k2_bob, kem->length_shared_secret);     //perform xor of k1 and k2

    uint8_t final_key[SHA256_DIGEST_LENGTH];
    Compute_SHA256(xor_result, kem->length_shared_secret, final_key);       //perform hashing of xor result

    //7. Write to 4 files 
    Write_Hex_File("bob_kyber_ciphertext.txt", ct_bob, kem->length_ciphertext);
    Write_Hex_File("bob_dilithium_signature.txt", sig_bob, sig_bob_len);
    Write_Hex_File("bob_k2.txt", k2_bob, kem->length_shared_secret);
    Write_Hex_File("bob_final_key.txt", final_key, SHA256_DIGEST_LENGTH);

    //memory cleanup
    OQS_KEM_free(kem);      // Frees an OQS_KEM object that was constructed by OQS_KEM_new
    OQS_SIG_free(sig);      // Frees an OQS_SIG object that was constructed by OQS_SIG_new
    free(k1_hex);
    free(alice_pk_hex);
    free(alice_pk);
    free(bob_sk_hex);
    free(bob_sk);
    free(k2_bob);
    free(ct_bob);
    free(sig_bob);
    free(k1_bytes);
    free(xor_result);

    return 0;
}

// Helper Functions

// Read file content
char* Read_File(const char *filename, long *fileLen) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *content = malloc(*fileLen + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    fread(content, 1, *fileLen, file);
    content[*fileLen] = '\0';
    fclose(file);
    return content;
}

// Convert hex string to bytes
int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len) {
    size_t hex_len = strlen(hex_input);
    int bytes = 0;
    for (size_t i = 0; i < hex_len; i += 2) {
        if (!isxdigit(hex_input[i]) || !isxdigit(hex_input[i+1])) {
            continue; 
        }
        if (bytes >= max_len) break; 
        sscanf(&hex_input[i], "%2hhx", &output[bytes]);
        bytes++;
    }
    return bytes;
}

// Convert bytes to hex string
void Convert_to_Hex(char *output, const uint8_t *input, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02X", input[i]);
    }
    output[len * 2] = '\0';
}

// Write to file
void Write_File(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot write to %s\n", filename);
        return;
    }
    fputs(content, file);
    fclose(file);
}

// Write hex file
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len) {
    char *hex_str = malloc(len * 2 + 1);
    if (!hex_str) return;
    Convert_to_Hex(hex_str, data, len);
    Write_File(filename, hex_str);
    free(hex_str);
}

// assumes output has enough space (len) and b1, b2 are of the same length.
void XOR_Bytes(uint8_t *output, const uint8_t *b1, const uint8_t *b2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = b1[i] ^ b2[i];
    }
}

// compute SHA256 hash
// output buffer `hash_output` must be at least SHA256_DIGEST_LENGTH bytes.
int Compute_SHA256(const uint8_t *data, size_t data_len, uint8_t *hash_output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int hash_len;

    md = EVP_sha256();
    if (md == NULL) {
        fprintf(stderr, "ERROR: EVP_sha256 failed.\n");
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new failed.\n");
        return 0;
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "ERROR: EVP_DigestInit_ex failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "ERROR: EVP_DigestUpdate failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash_output, &hash_len)) {
        fprintf(stderr, "ERROR: EVP_DigestFinal_ex failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);

    if (hash_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "ERROR: SHA256 output length mismatch (got %u, expected %d).\n", hash_len, SHA256_DIGEST_LENGTH);
        return 0;
    }
    return 1;
}