#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h> // for SHA256()
#include <stdio.h>
#include <stdlib.h>

#define SECP192K1_HEX_LEN 98

// Function prototypes
char *Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char *SHA256(const unsigned char *data, size_t count,
                      unsigned char *md_buf);

int main(int argc, char *argv[]) {
  /* --- Setup 0: Setup Variables --- */
  int exit_code = EXIT_FAILURE;
  BIGNUM *random_k_bignum = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *C = NULL, *C_prime = NULL, *PK = NULL, *P_m = NULL, *D = NULL;
  char *random_k_hex = NULL, *PK_hex = NULL, *message_hex = NULL;
  char *C_hex = NULL, *D_hex = NULL, *G_hex = NULL;
  char *concat = NULL;
  BIGNUM *priv_bn = NULL;
  EC_KEY *eckey = NULL;
  EC_POINT *pub = NULL;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned char *sig = NULL;
  unsigned int sig_len = 0;
  char *sig_hex = NULL;

  // --- Step 1: Create a BN context ---
  // BN_CTX is a structure used by OpenSSL to hold temporary BIGNUM variables
  // for efficient memory management
  BN_CTX *bn_ctx = BN_CTX_new();

  // --- Step 2: Get 128 bit Random number (k) ---
  int random_k_hex_len;
  random_k_hex = (char *)Read_File(argv[3], &random_k_hex_len);
  if (!BN_hex2bn(&random_k_bignum, random_k_hex)) {
    fprintf(stderr, "BN_hex2bn failed on random_k_hex\n");
    goto cleanup;
  }

  // --- Step 3a: Create a new EC_GROUP object using the NID for secp192k1 ---
  group = EC_GROUP_new_by_curve_name(NID_secp192k1);
  if (!group) {
    fprintf(stderr, "Error creating EC_GROUP\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 3b: Get the generator (G) point of the group ---
  const EC_POINT *G = EC_GROUP_get0_generator(group);
  if (!G) {
    fprintf(stderr, "Error getting generator\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 4: Compute C = k * G ---
  C = EC_POINT_new(group);
  if (!C) {
    fprintf(stderr, "EC_POINT_new C failed\n");
    goto cleanup;
  }
  if (!EC_POINT_mul(group, C, random_k_bignum, NULL, NULL, bn_ctx)) {
    fprintf(stderr, "EC_POINT_mul failed. Error computing C\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // -- Step 5: Get the public key (PK) point on the EC curve ---
  int PK_hex_len;
  PK_hex = (char *)Read_File(argv[1], &PK_hex_len);
  PK = EC_POINT_new(group);
  if (!EC_POINT_hex2point(group, PK_hex, PK, bn_ctx)) {
    fprintf(stderr, "Error converting PK hex to EC_POINT\n");
    goto cleanup;
  }

  // --- Step 6: Compute C' = k * PK ---
  C_prime = EC_POINT_new(group);
  if (!C_prime) {
    fprintf(stderr, "EC_POINT_new C_prime failed\n");
    goto cleanup;
  }
  if (!EC_POINT_mul(group, C_prime, NULL, PK, random_k_bignum, bn_ctx)) {
    fprintf(stderr, "EC_POINT_mul failed. Error computing C' = k * PK\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 7: Get the message point (P_m) ---
  // message -> H(message) -> Hex(H(message)) -> hex2point(Hex(H(message)))
  int message_hex_len;
  message_hex = (char *)Read_File(argv[4], &message_hex_len);
  P_m = EC_POINT_new(group);
  if (!EC_POINT_hex2point(group, message_hex, P_m, bn_ctx)) {
    fprintf(stderr, "Error converting message hex to EC_POINT\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 8: Compute D = C' + P_m ---
  D = EC_POINT_new(group);
  if (!D) {
    fprintf(stderr, "EC_POINT_new D failed\n");
    goto cleanup;
  }
  if (!EC_POINT_add(group, D, C_prime, P_m, bn_ctx)) {
    fprintf(stderr, "EC_POINT_add failed\n");
    goto cleanup;
  }

  // --- Optional: To verify or display G, C and D, we can print it in hex ---
  G_hex = EC_POINT_point2hex(group, G, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!G_hex) {
    fprintf(stderr, "Error converting G to hex.\n");
    goto cleanup;
  }
  C_hex = EC_POINT_point2hex(group, C, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!C_hex) {
    fprintf(stderr, "Error converting C to hex.\n");
    goto cleanup;
  }
  D_hex = EC_POINT_point2hex(group, D, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!D_hex) {
    fprintf(stderr, "Error converting D to hex.\n");
    goto cleanup;
  }
  printf("Generator G:\n  %s\n", G_hex);
  printf("C:\n  %s\n", C_hex);
  printf("D:\n  %s\n", D_hex);

  // --- Step 9: Save C and D ---
  Write_File("alice_c.txt", C_hex);
  Write_File("alice_d.txt", D_hex);

  // --- Step 10: Get & convert Alice's ECDSA secret key from hex to BIGNUM ---
  int alice_sk_hex_len;
  char *alice_sk_hex = Read_File(argv[2], &alice_sk_hex_len);
  priv_bn = BN_new();
  if (!priv_bn) {
    fprintf(stderr, "BN_new priv_bn failed\n");
    goto cleanup;
  }
  if (BN_hex2bn(&priv_bn, alice_sk_hex) == 0) {
    fprintf(stderr, "BN_hex2bn failed for alice secret\n");
    goto cleanup;
  }

  // --- Step 11: Set private key in EC_KEY ---
  eckey = EC_KEY_new();
  if (!eckey) {
    fprintf(stderr, "EC_KEY_new failed\n");
    goto cleanup;
  }
  if (!EC_KEY_set_group(eckey, group)) {
    fprintf(stderr, "EC_KEY_set_group failed\n");
    goto cleanup;
  }
  if (!EC_KEY_set_private_key(eckey, priv_bn)) {
    fprintf(stderr, "EC_KEY_set_private_key failed\n");
    goto cleanup;
  }

  // --- Step 12: Compute public key point = priv * G and set in EC_KEY ---
  pub = EC_POINT_new(group);
  if (!pub) {
    fprintf(stderr, "EC_POINT_new pub failed\n");
    goto cleanup;
  }
  if (!EC_POINT_mul(group, pub, priv_bn, NULL, NULL, bn_ctx)) {
    fprintf(stderr, "EC_POINT_mul to compute public failed\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }
  if (!EC_KEY_set_public_key(eckey, pub)) {
    fprintf(stderr, "EC_KEY_set_public_key failed\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 13a: Concatenate hex strings C||D (text, not decoded) ---
  size_t C_len = strlen(C_hex);
  size_t D_len = strlen(D_hex);
  concat = malloc(C_len + D_len + 1);
  if (!concat) {
    fprintf(stderr, "OOM\n");
    goto cleanup;
  }
  memcpy(concat, C_hex, C_len);
  memcpy(concat + C_len, D_hex, D_len);
  concat[C_len + D_len] = '\0';

  // --- Step 13b: Hash (C||D) ---
  // Use SHA-256 to derive a 32-byte private key from C||D
  // This ensures uniform randomness across 256-bit key space
  SHA256((unsigned char *)concat, strlen(concat), digest);

  // --- Step 14a: Allocate buffer for signature (DER) ---
  // ECDSA_size gives upper bound
  sig_len = (unsigned int)ECDSA_size(eckey);
  sig = malloc(sig_len);
  if (!sig) {
    fprintf(stderr, "OOM\n");
    goto cleanup;
  }

  // --- Step 15b: Sign the SHA256 digest ---
  if (ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, sig, &sig_len, eckey) != 1) {
    fprintf(stderr, "ECDSA_sign failed\n");
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  // --- Step 16: Convert DER signature to hex and write to file ---
  sig_hex = (char *)malloc(sig_len * 2 + 1);
  Convert_to_Hex(sig_hex, sig, sig_len);
  if (!sig_hex) {
    fprintf(stderr, "bytes_to_hex failed\n");
    goto cleanup;
  }

  // --- Step 17: Verify & save signature hex ---
  printf("Signature:\n  %s\n", sig_hex);
  Write_File("alice_signature.txt", sig_hex);

  exit_code = EXIT_SUCCESS;

cleanup:
  // --- Step 18: CLEANUP ---
  if (sig)
    free(sig);
  if (sig_hex)
    free(sig_hex);
  if (pub)
    EC_POINT_free(pub);
  if (eckey)
    EC_KEY_free(eckey);
  if (priv_bn)
    BN_free(priv_bn);

  if (C_hex)
    OPENSSL_free(C_hex);
  if (D_hex)
    OPENSSL_free(D_hex);
  if (G_hex)
    OPENSSL_free(G_hex);

  if (C)
    EC_POINT_free(C);
  if (C_prime)
    EC_POINT_free(C_prime);
  if (PK)
    EC_POINT_free(PK);
  if (P_m)
    EC_POINT_free(P_m);
  if (D)
    EC_POINT_free(D);

  if (random_k_bignum)
    BN_free(random_k_bignum);
  if (bn_ctx)
    BN_CTX_free(bn_ctx);
  if (group)
    EC_GROUP_free(group);

  if (random_k_hex)
    free(random_k_hex);
  if (PK_hex)
    free(PK_hex);
  if (message_hex)
    free(message_hex);
  if (alice_sk_hex)
    free(alice_sk_hex);
  if (concat)
    free(concat);

  return exit_code;
}

/*============================
        Read from File
==============================*/
char *Read_File(char fileName[], int *fileLen) {
  FILE *pFile;
  pFile = fopen(fileName, "r");
  if (pFile == NULL) {
    printf("Error opening file.\n");
    exit(0);
  }
  fseek(pFile, 0L, SEEK_END);
  int temp_size = ftell(pFile) + 1;
  fseek(pFile, 0L, SEEK_SET);
  char *output = (char *)malloc(temp_size);
  fgets(output, temp_size, pFile);
  fclose(pFile);

  *fileLen = temp_size - 1;
  return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]) {
  FILE *pFile;
  pFile = fopen(fileName, "w");
  if (pFile == NULL) {
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}

/*============================
        Convert to Hex
        Note: make sure output array size is double the size of input
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
  const char hex_digits[] = "0123456789abcdef";
  for (int i = 0; i < inputlength; i++) {
    output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F]; // high nibble
    output[2 * i + 1] = hex_digits[input[i] & 0x0F];    // low nibble
  }
}
