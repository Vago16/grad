#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "utils.c"

int main() {
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) { fprintf(stderr,"BN_CTX_new failed\n"); return 1; }

    // --- Step 1: Read Alice's public key ---
    int pk_len;
    char *alice_pk_hex = Read_File("alice/key_pk_hex.txt", &pk_len);
    if (!alice_pk_hex) { fprintf(stderr,"alice/key_pk_hex.txt not found\n"); return 1; }

    // --- Step 2: Create EC_KEY object ---
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    // --- Step 3: Convert hex to EC_POINT ---
    EC_POINT *pk_point = EC_POINT_new(group);
    if (!EC_POINT_hex2point(group, alice_pk_hex, pk_point, bn_ctx)) {
        fprintf(stderr, "Error converting Alice's public key from hex.\n");
        return 1;
    }

    // --- Step 4: Addition P + P ---
    EC_POINT *add_point = EC_POINT_new(group);
    if (!EC_POINT_add(group, add_point, pk_point, pk_point, bn_ctx)) {
        fprintf(stderr,"EC_POINT_add failed\n"); return 1;
    }

    char *add_hex = EC_POINT_point2hex(group, add_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
    Write_File("point_addition/add_output.txt", add_hex);

    // --- Step 5: Multiplication 2 * P ---
    EC_POINT *mul_point = EC_POINT_new(group);
    BIGNUM *k = BN_new();
    BN_set_word(k, 2);
    if (!EC_POINT_mul(group, mul_point, NULL, pk_point, k, bn_ctx)) {
        fprintf(stderr,"EC_POINT_mul failed\n"); return 1;
    }

    char *mul_hex = EC_POINT_point2hex(group, mul_point, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
    Write_File("point_addition/mul_output.txt", mul_hex);

    // --- Step 6: Cleanup ---
    OPENSSL_free(add_hex);
    OPENSSL_free(mul_hex);
    EC_POINT_free(pk_point);
    EC_POINT_free(add_point);
    EC_POINT_free(mul_point);
    EC_KEY_free(eckey);
    BN_free(k);
    BN_CTX_free(bn_ctx);
    free(alice_pk_hex);

    printf("Done: add_output.txt (P+P), mul_output.txt (2*P)\n");
    return 0;
}
