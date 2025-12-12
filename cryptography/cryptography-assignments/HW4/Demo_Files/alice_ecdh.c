#include "utils.c" // Utility functions: Read_File, Write_File, Convert_to_Hex
#include <openssl/ec.h>  // Elliptic Curve structures and functions
#include <openssl/err.h> // For OpenSSL error reporting
#include <openssl/evp.h> // High-level OpenSSL API for cryptographic operations
#include <openssl/sha.h> // SHA256 hash function
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  // --- Step 0: Check for seed file argument ---
  if (argc < 2) {
    printf("Please enter seed file name.\n");
    return 0;
  }

  // --- Step 1: Create a BN context ---
  // BN_CTX is a structure used by OpenSSL to hold temporary BIGNUM variables
  // for efficient memory management
  BN_CTX *bn_ctx = BN_CTX_new();

  // --- Step 2: Read seed file ---
  // This seed will be used to deterministically derive Alice's private key
  int seed_len;
  unsigned char *seed_str = Read_File(argv[1], &seed_len);
  if (seed_len < 32) {
    printf("Seed Length must be at least 32 bytes.\n");
    return 0;
  }

  // --- Step 3: Hash the seed to generate private key ---
  // Use SHA-256 to derive a 32-byte private key from the seed
  // This ensures uniform randomness across 256-bit key space
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(seed_str, 32, hash); // SHA256(input, input_length, output)

  // --- Step 4: Convert private key to hex for storage ---
  // Hex representation makes it human-readable and portable
  char sk_hex[2 * SHA256_DIGEST_LENGTH +
              1]; // 2 chars per byte + null terminator
  Convert_to_Hex(sk_hex, hash, SHA256_DIGEST_LENGTH);
  sk_hex[2 * SHA256_DIGEST_LENGTH] = '\0'; // Null-terminate string
  Write_File("alice/key_sk_hex.txt",
             sk_hex); // Save private key hex to file (for demonstration)

  // --- Step 5: Convert hex to BIGNUM ---
  // OpenSSL's BN_hex2bn converts hex string to a BIGNUM (arbitrary-length
  // integer)
  BIGNUM *sk = BN_new();
  BN_hex2bn(&sk, sk_hex);

  // --- Step 6: Generate EC key ---
  // Create a new EC_KEY structure for the secp256k1 curve
  EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  // Get the associated EC_GROUP object (contains curve parameters)
  const EC_GROUP *group = EC_KEY_get0_group(eckey);

  // --- Step 7: Compute Alice's public key ---
  // Public key = sk * G, where G is the base point of the curve
  // OpenSSL function: EC_POINT_mul(group, R, n, Q, m, ctx) computes R = n*G +
  // m*Q Here, n=sk, Q=NULL, m=NULL, so pk_point = sk*G
  EC_POINT *pk_point = EC_POINT_new(group); // Allocate point structure
  if (!EC_POINT_mul(group, pk_point, sk, NULL, NULL, bn_ctx)) {
    fprintf(stderr, "Error computing public key.\n");
    return 1;
  }

  // --- Step 8: Convert public key to uncompressed hex ---
  // POINT_CONVERSION_UNCOMPRESSED stores full (x,y) coordinates
  // pk_hex = "04 || X || Y" format in hex
  char *pk_hex = EC_POINT_point2hex(group, pk_point,
                                    POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!pk_hex) {
    fprintf(stderr, "Error converting public key to hex.\n");
    return 1;
  }

  // Optionally, you can extract x and y separately using
  // EC_POINT_get_affine_coordinates_GFp() This function gives the actual affine
  // coordinates of the point on the curve

  // --- Step 9: Save Alice's public key ---
  Write_File("alice/key_pk_hex.txt", pk_hex);

  // --- Step 10: Read Bob's public key ---
  int bob_pk_len;
  char *bob_pk_hex = Read_File("bob/key_pk_hex.txt", &bob_pk_len);
  if (!bob_pk_hex) {
    printf("Alice: bob/key_pk_hex.txt not found yet. Run Bob.\n");
    return 0;
  }

  // --- Step 11: Convert Bob's public key from hex to EC_POINT ---
  EC_POINT *bob_pk_point = EC_POINT_new(group); // Allocate new point
  if (!EC_POINT_hex2point(group, bob_pk_hex, bob_pk_point, bn_ctx)) {
    fprintf(stderr, "Error converting Bob's public key from hex.\n");
    return 1;
  }

  // --- Step 12: Compute shared secret ---
  // ECDH: Shared secret = sk * Bob_PK
  // EC_POINT_mul: r = n*G + m*Q
  // Here, n=NULL, m=sk, Q=Bob's public key
  EC_POINT *secret_point = EC_POINT_new(group);
  if (!EC_POINT_mul(group, secret_point, NULL, bob_pk_point, sk, bn_ctx)) {
    fprintf(stderr, "Error computing shared secret.\n");
    return 1;
  }

  // --- Step 13: Convert shared secret to hex for storage ---
  char *secret_hex = EC_POINT_point2hex(group, secret_point,
                                        POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!secret_hex) {
    fprintf(stderr, "Error converting shared secret to hex.\n");
    return 1;
  }

  Write_File("alice/secret_hex.txt", secret_hex);

  // --- Step 14: Cleanup ---
  // Free all dynamically allocated resources to avoid memory leaks
  OPENSSL_free(pk_hex);
  OPENSSL_free(secret_hex);
  EC_POINT_free(pk_point);
  EC_POINT_free(bob_pk_point);
  EC_POINT_free(secret_point);
  EC_KEY_free(eckey);
  BN_free(sk);
  BN_CTX_free(bn_ctx);
  free(seed_str);
  free(bob_pk_hex);

  printf("Alice: Shared secret computed and saved to alice/secret_hex.txt\n");
  return 0;
}
