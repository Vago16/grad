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
    if (argc != 6) {
        printf("Must put in k1_ab.txt, bob_dilithium_public.txt, and alice_kyber_private.txt as command line arguments.\n");        //accidentally put as bob_dilithium_private.txt in assignment notes about compiling
        return 1;
    }

    //liboqs functions
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);      // Constructs an OQS_KEM object for a particular algorithm
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);        //// Constructs an OQS_SIG object for a particular algorithm

    //initialize command line arguments
    const char *bob_pk_file   = argv[1];
    const char *alice_sk_file = argv[2];
    const char *k1_file       = argv[5];

    //for invalid signature checking
    const char *sig_file = argv[3];

    
    //1. Alice reads K1 from file: k1_ab.txt
    long k1_len;        //variable to store length of string in text for reading
    char *k1_hex = Read_File(k1_file, &k1_len);

    //check for improper key size
    if ((size_t)(k1_len / 2) != (size_t)kem->length_shared_secret) {
        printf("Improper key size for k1\n");
        return 1;
    }

    //2. Alice reads Bob’s Dilithium public key (bob dilithium public.txt) from file
    long bob_pk_hex_len;
    char *bob_pk_hex = Read_File(bob_pk_file, &bob_pk_hex_len);

    //check for improper key size
    if ((size_t)(bob_pk_hex_len / 2) != (size_t)sig->length_public_key) {
        printf("Improper key size for Bob's public key\n");
        return 1;
    }

    uint8_t *bob_pk = malloc(sig->length_public_key);
    Convert_from_Hex(bob_pk, bob_pk_hex, sig->length_public_key);

    //3. Alice reads her Kyber private key (alice kyber private.txt) from file

    long alice_sk_hex_len;
    char *alice_sk_hex = Read_File(alice_sk_file, &alice_sk_hex_len);

    //check for improper key size
    if ((size_t)(alice_sk_hex_len / 2) != (size_t)kem->length_secret_key) {
        printf("Improper key size for Alice's private key");
        return 1;
    }

    uint8_t *alice_sk = malloc(kem->length_secret_key);
    Convert_from_Hex(alice_sk, alice_sk_hex, kem->length_secret_key);

    //4. Alice reads the Dilithium signature (σB ) from bob dilithium signature.txt

    long sig_hex_len;
    char *sig_hex = Read_File(sig_file, &sig_hex_len);

    //5. Alice reads the Kyber ciphertext (CTB ) from bob dilithium signature.txt
    long ct_hex_len;
    char *ct_hex = Read_File("bob_kyber_ciphertext.txt", &ct_hex_len);

    //bob must have run first, if not, abort program as txt file will not be present
    if (!sig_hex) {
        printf("The executable file \"bob\" has not been run yet so bob_dilithium_signature.txt does not exist\n");
        return 1;
    }

    if (!ct_hex) {
        printf("The executable file \"bob\" has not been run yet bob_kyber_ciphertext.txt\n");
        return 1;
    } 

    //Use the provided functions to convert signature and ciphertext to byte arrays
    uint8_t *signature = malloc(sig->length_signature);
    int sig_bytes = Convert_from_Hex(signature, sig_hex, sig->length_signature);
    uint8_t *ct = malloc(kem->length_ciphertext);
    int ct_bytes = Convert_from_Hex(ct, ct_hex, kem->length_ciphertext);

    //Verify the lengths of the ciphertext and signature match the expected lengths defined by liboqs
    if ((size_t)sig_bytes > (size_t)sig->length_signature || sig_bytes <= 0){
        printf("Length of singature does not match expected length\n");
        return 1;
    }

    if ((size_t)ct_bytes != (size_t)kem->length_ciphertext) {
        printf("Length of ciphertext does not match expected length\n");
    }


    //6. Using Bob’s Dilithium public key, Alice verifies the signature (σB )
    //If signature verification fails, Alice MUST abort the program, and should NOT proceed to decrypt the ciphertext
    //use Signature verification algorithm
    if (OQS_SIG_verify(sig, ct, kem->length_ciphertext, signature, (size_t)sig_bytes, bob_pk) != OQS_SUCCESS) {
        printf("Verification failed, aborting program");
        return 1;
    }

    //7. Decapsulate the Kyber ciphertext (CTB ) using Alice’s own Kyber private key alice kyber private.txt to derive the shared secret (K2) Convert K2A to Hex string 
    uint8_t *k2_alice = malloc(kem->length_shared_secret);      //shared secret
    OQS_KEM_decaps(kem, k2_alice, ct, alice_sk);        // Decapsulation algorithm

    //and write to file called k2 alice.txt
    Write_Hex_File("alice_k2.txt", k2_alice, kem->length_shared_secret);

    //8. Compute the final shared key as: H(K1 ⊕ K2) and write the result to file as alice_final_key.txt
    uint8_t *k1_bytes = malloc(kem->length_shared_secret);
    Convert_from_Hex(k1_bytes, k1_hex, kem->length_shared_secret);      //convert k1 to bytes

    //XOR the two shared secrets K1 and K2
    uint8_t *xor_buf = malloc(kem->length_shared_secret);       //holds space for xor result
    XOR_Bytes(xor_buf, k1_bytes, k2_alice, kem->length_shared_secret);

    //Apply SHA-256 hash function to the result
    uint8_t final_hash[SHA256_DIGEST_LENGTH];
    Compute_SHA256(xor_buf, kem->length_shared_secret, final_hash);


    //9. Write to 2 files

    //Write_Hex_File("k2_bob.txt", k2_alice, kem->length_shared_secret);    //instructions say to write to k2_bob.txt but bob already wwrote to it, mispelling?
    Write_Hex_File("alice_final_key.txt", final_hash, SHA256_DIGEST_LENGTH);        //Final key
    printf("Finished writing\n");

    //memory cleanup
    OQS_KEM_free(kem);      // Frees an OQS_KEM object that was constructed by OQS_KEM_new
    OQS_SIG_free(sig);      // Frees an OQS_SIG object that was constructed by OQS_SIG_new
    free(k1_hex);
    free(bob_pk_hex);
    free(bob_pk);
    free(alice_sk_hex);
    free(alice_sk);
    free(sig_hex);
    free(ct_hex);
    free(signature);
    free(ct);
    free(k2_alice);
    free(k1_bytes);
    free(xor_buf);


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