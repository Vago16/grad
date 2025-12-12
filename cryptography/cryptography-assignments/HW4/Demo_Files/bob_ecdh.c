#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>    // Elliptic Curve structures and operations (EC_KEY, EC_GROUP, EC_POINT)
#include <openssl/evp.h>   // High-level cryptographic API for key derivation, encryption, signing, etc.
#include <openssl/err.h>   // OpenSSL error reporting
#include <openssl/sha.h>   // SHA256 hash function
#include "utils.c"          // Custom utility functions: Read_File, Write_File, Convert_to_Hex

int main(int argc, char *argv[]){
    // --- Step 0: Check for seed file argument ---
    if (argc < 2) 
    {
        printf("Please enter seed file name.\n");
        return 0;
    }
    
    // --- Step 1: Create a BN context ---
    // BN_CTX is a structure used by OpenSSL to hold temporary BIGNUM variables for modular arithmetic.
    BN_CTX *bn_ctx = BN_CTX_new();

    // --- Step 2: Read seed file ---
    // Bob reads a seed from a file to deterministically derive his private key
    int seed_len;
    unsigned char *seed_str = Read_File(argv[1], &seed_len);
    if (seed_len < 32) 
    {
        printf("Seed Length must be at least 32 bytes.\n");
        return 0;
    }

    // --- Step 3: Hash the seed to generate private key ---
    // Using SHA-256 ensures a uniformly distributed 256-bit private key
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(seed_str, 32, hash); // Hash the first 32 bytes of the seed

    // --- Step 4: Convert private key to hex for storage ---
    // Hex format makes it human-readable and easier to store/transmit
    char sk_hex[2 * SHA256_DIGEST_LENGTH + 1]; // 2 chars per byte + null terminator
    Convert_to_Hex(sk_hex, hash, SHA256_DIGEST_LENGTH);
    sk_hex[2 * SHA256_DIGEST_LENGTH] = '\0';  // Null-terminate string
    Write_File("bob/key_sk_hex.txt", sk_hex); // Save private key hex to file

    // --- Step 5: Convert hex to BIGNUM ---
    // OpenSSL uses BIGNUM (arbitrary-length integer) for scalar operations
    BIGNUM *sk = BN_new(); 
    BN_hex2bn(&sk, sk_hex); 

    // --- Step 6: Generate EC key ---
    // Create an EC_KEY object for the secp256k1 curve
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1); 
    // Retrieve the curve parameters (EC_GROUP) associated with this key
    const EC_GROUP *group = EC_KEY_get0_group(eckey); 

    // --- Step 7: Compute Bob's public key ---
    // Public key = sk * G, where G is the generator/base point of the curve
    // EC_POINT_mul(group, R, n, Q, m, ctx) computes R = n*G + m*Q
    // Here, n=sk, Q=NULL, m=NULL, so pk_point = sk*G
    EC_POINT *pk_point = EC_POINT_new(group); // Allocate memory for the point
    if (!EC_POINT_mul(group, pk_point, sk, NULL, NULL, bn_ctx)) {
        fprintf(stderr, "Error computing public key.\n");
        return 1;
    }

    // --- Step 8: Convert public key to uncompressed hex ---
    // Uncompressed format stores full coordinates: 0x04 || X || Y
    char *pk_hex = EC_POINT_point2hex(group, pk_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
    if (!pk_hex) {
        fprintf(stderr, "Error converting public key to hex.\n");
        return 1;
    }

    // --- Step 9: Save Bob's public key ---
    Write_File("bob/key_pk_hex.txt", pk_hex);

    // --- Step 10: Read Alice's public key ---
    int alice_pk_len;
    char *alice_pk_hex = Read_File("alice/key_pk_hex.txt", &alice_pk_len);
    if (!alice_pk_hex) {
        printf("Bob: alice/key_pk_hex.txt not found yet. Run Alice.\n");
        return 0;
    }

    // --- Step 11: Convert Alice's public key from hex to EC_POINT ---
    EC_POINT *alice_pk_point = EC_POINT_new(group); // Allocate point
    if (!EC_POINT_hex2point(group, alice_pk_hex, alice_pk_point, bn_ctx)) {
        fprintf(stderr, "Error converting Alice's public key from hex.\n");
        return 1;
    }

    // --- Step 12: Compute shared secret ---
    // ECDH: Shared secret = sk_B * Alice_PK
    // EC_POINT_mul(group, R, n, Q, m, ctx) => R = n*G + m*Q
    // Here, n=NULL, m=sk, Q=Alice's public key => secret_point = sk*Alice_PK
    EC_POINT *secret_point = EC_POINT_new(group);
    if (!EC_POINT_mul(group, secret_point, NULL, alice_pk_point, sk, bn_ctx)) {
        fprintf(stderr, "Error computing shared secret.\n");
        return 1;
    }

    // --- Step 13: Convert shared secret to hex ---
    char *secret_hex = EC_POINT_point2hex(group, secret_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
    if (!secret_hex) {
        fprintf(stderr, "Error converting shared secret to hex.\n");
        return 1;
    }

    // --- Step 14: Save shared secret ---
    Write_File("bob/secret_hex.txt", secret_hex);

    // --- Step 15: Cleanup ---
    // Free all allocated memory to avoid leaks
    OPENSSL_free(pk_hex);
    OPENSSL_free(secret_hex);
    EC_POINT_free(pk_point);
    EC_POINT_free(alice_pk_point);
    EC_POINT_free(secret_point);
    EC_KEY_free(eckey);
    BN_free(sk);
    BN_CTX_free(bn_ctx);
    free(seed_str);
    free(alice_pk_hex);

    printf("Bob: Shared secret computed and saved to bob/secret_hex.txt\n");
    return 0;
}
