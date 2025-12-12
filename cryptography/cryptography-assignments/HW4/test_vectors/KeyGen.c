#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h> // for SHA256()
#include <stdio.h>
#include <stdlib.h>

// Function prototypes
char *Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char *SHA256(const unsigned char *data, size_t count,
                      unsigned char *md_buf);

int main(int argc, char *argv[]) {
  // --- Step 1: Create a BN context ---
  // BN_CTX is a structure used by OpenSSL to hold temporary BIGNUM variables
  // for efficient memory management
  BN_CTX *bn_ctx = BN_CTX_new();

  // --- Step 2: Read seed file ---
  // This 32-byte seed will be used to deterministically derive Alice's private
  // key
  int seed_len;
  char *seed_str = Read_File(argv[1], &seed_len);
  if (seed_len < 32) {
    printf("Seed Length must be at least 32 bytes.\n");
    return EXIT_FAILURE;
  }

  // --- Step 3: Hash the seed to generate private key (y) ---
  // Use SHA-256 to derive a 32-byte private key from the seed
  // This ensures uniform randomness across 256-bit key space
  unsigned char y[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char *)seed_str, 32, y);

  // --- Step 4: Convert private key to hex for storage ---
  // Hex representation makes it human-readable and portable
  char y_hex[SHA256_DIGEST_LENGTH * 2 + 1];
  Convert_to_Hex(y_hex, y, SHA256_DIGEST_LENGTH);

  // --- Step 5: Convert hex to BIGNUM ---
  // OpenSSL's BN_hex2bn converts hex string to a BIGNUM (arbitrary-length
  // integer)
  BIGNUM *y_bignum = BN_new();
  BN_hex2bn(&y_bignum, y_hex);

  // --- Step 6a: Create a new EC_GROUP object using the NID for secp192k1 ---
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp192k1);
  if (group == NULL) {
    fprintf(stderr, "Error creating EC_GROUP\n");
    ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }

  // --- Step 6b: Get the generator (G) point of the group ---
  const EC_POINT *G = EC_GROUP_get0_generator(group);
  if (G == NULL) {
    fprintf(stderr, "Error getting generator\n");
    ERR_print_errors_fp(stderr);
    EC_GROUP_free(group);
    return EXIT_FAILURE;
  }

  // --- Step 6c: To verify or display G, we can print it in hex ---
  char *gen_hex =
      EC_POINT_point2hex(group, G, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (gen_hex != NULL) {
    printf("Generator G:\n  %s\n", gen_hex);
    OPENSSL_free(gen_hex);
  }

  // --- Step 7: Compute PK = y * G ---
  EC_POINT *PK = EC_POINT_new(group);
  if (!EC_POINT_mul(group, PK, y_bignum, NULL, NULL, bn_ctx)) {
    fprintf(stderr, "Error computing public key\n");
    ERR_print_errors_fp(stderr);
    BN_free(y_bignum);
    EC_POINT_free(PK);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return EXIT_FAILURE;
  }

  // --- Step 8: Convert public key to uncompressed hex ---
  // POINT_CONVERSION_UNCOMPRESSED stores full (x,y) coordinates
  // PK_hex = "04 || X || Y" format in hex
  char *PK_hex =
      EC_POINT_point2hex(group, PK, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  if (!PK_hex) {
    fprintf(stderr, "Error converting public key to hex.\n");
    OPENSSL_free(PK_hex);
    return EXIT_FAILURE;
  }

  // --- Step 9: Log & store private and public keys ---
  printf("Private key (y):\n  %s\n", y_hex);
  printf("Public key (PK = y * G):\n  %s\n", PK_hex);
  Write_File("SK_Hex.txt", y_hex);
  Write_File("PK_Hex.txt", PK_hex);
  OPENSSL_free(PK_hex);

  // --- Step 10: Clean up ---
  BN_free(y_bignum);
  EC_POINT_free(PK);
  BN_CTX_free(bn_ctx);
  EC_GROUP_free(group);
  return 0;
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
