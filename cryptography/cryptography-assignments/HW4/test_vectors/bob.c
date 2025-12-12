#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// function prototypes
char *Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

int main(int argc, char *argv[]) {
  // ECDSA Verification step//
  // initialize length variables for reading files
  int sig_length, C_length, D_length, pub_length, sh_length;
  // reading given files
  char *hex_alice_sig;
  char *hex_C;
  char *hex_D;
  char *hex_alice_pub_key;
  char *hex_sk;

  hex_sk = Read_File(argv[1], &sh_length); // reads bob's private key
  hex_alice_pub_key = Read_File(
      argv[2], &pub_length); // reads alice's public key as EC point hex
  hex_C = Read_File(argv[3], &C_length);           // reads ciphertext
  hex_D = Read_File(argv[4], &D_length);           // reads ciphertext
  hex_alice_sig = Read_File(argv[5], &sig_length); // reads alice's signature

  // concatenation of the two ciphertext files (C||D)
  char concat_ctext[4096]; // array that will hold concatenation, larger than
                           // necessary to prevent overflow when concatenating
  snprintf(concat_ctext, sizeof(concat_ctext), "%s%s", hex_C,
           hex_D); // sprintf used to concatenate and copy into a new variable
                   // at the same time

  // hashing of the concatenation H(C||D)
  unsigned char
      concat_hashed[SHA256_DIGEST_LENGTH]; // array to store256 bits after the
                                           // concatenation get hashed
  SHA256(
      (unsigned char *)concat_ctext, strlen(concat_ctext),
      concat_hashed); // use SHA256 algorithm to hash the concatenated hex files

  // initalize variables for OpenSSL functions using elliptic curves for the
  // verification process
  BN_CTX *bn_ctx =
      BN_CTX_new(); // stores BIGNUM variables temporarily during OpenSSL
                    // functions
                    // https://docs.openssl.org/master/man3/BN_CTX_new/
  EC_GROUP *ell_group = EC_GROUP_new_by_curve_name(
      NID_secp192k1); // elliptic curve definition variable
                      // https://docs.openssl.org/master/man3/EC_GROUP_new/#description

  // convert the signature to bytes and record the length also(both needed for
  // the elliptic curve public key)
  unsigned char alice_sig_bytes[256]; // will hold the bytes of the signature
  int alice_sig_length = 0; // will hold how many bytes the signature is

  // iterate over and increment the length and puts recorded bytes into the byte
  // variable
  for (int i = 0; i < strlen(hex_alice_sig) / 2; i++) {
    sscanf(&hex_alice_sig[2 * i], "%2hhx", &alice_sig_bytes[i]);
    alice_sig_length++;
  }

  // use EC functions from OpenSSL library to rebuild Alice's public key
  EC_POINT *alice_pub_key = EC_POINT_new(ell_group); // create EC point on curve
  EC_POINT_hex2point(ell_group, hex_alice_pub_key, alice_pub_key,
                     bn_ctx); // EC_POINT to hex conversion
  EC_KEY *eckey_alice = EC_KEY_new_by_curve_name(NID_secp192k1); // key to
                                                                 // verify
  EC_KEY_set_group(eckey_alice, ell_group);          // set group from key
  EC_KEY_set_public_key(eckey_alice, alice_pub_key); // set public key

  // verify signature with ECDSA
  int verification = ECDSA_verify(0, concat_hashed, SHA256_DIGEST_LENGTH,
                                  alice_sig_bytes, alice_sig_length,
                                  eckey_alice); // store value of verification

  // if verification failed, exit program
  if (verification != 1) {
    printf("Exiting because of invalid signature.\n");
    // free up memory
    free(hex_alice_sig);
    free(hex_C);
    free(hex_D);
    free(hex_alice_pub_key);
    free(hex_sk);
    EC_KEY_free(
        eckey_alice); // frees up memory for EC_KEY objects
                      // https://docs.openssl.org/master/man3/EC_KEY_new/#description
    EC_GROUP_free(ell_group); // frees up memory for EC_GROUP objects
    BN_CTX_free(bn_ctx);      // frees up memory for BN_CTX objects
    return EXIT_FAILURE;
  }

  // ElGamal Decryption: Bob step//
  // 1-3 Reading has already done above
  // then convert C and D to EC_POINTS for decryption
  EC_POINT *ec_C = EC_POINT_new(ell_group);
  EC_POINT *ec_D = EC_POINT_new(ell_group);

  // convert EC points to hex
  EC_POINT_hex2point(ell_group, hex_C, ec_C, bn_ctx);
  EC_POINT_hex2point(ell_group, hex_D, ec_D, bn_ctx);

  // convert sk to BIGNUM for decryption
  BIGNUM *bob_sk = NULL;
  BN_hex2bn(&bob_sk, hex_sk); // BIGNUM to hex conversion

  // 4. Perform C^a = y.C, using elliptic curve multiplication
  EC_POINT *C_alpha = EC_POINT_new(ell_group);
  EC_POINT_mul(ell_group, C_alpha, NULL, ec_C, bob_sk,
               bn_ctx); // EC Point Multiplication for the computation

  // 5. Perform Pm = D - C^a
  EC_POINT *pm = EC_POINT_new(ell_group);
  EC_POINT_invert(ell_group, C_alpha, bn_ctx);
  EC_POINT_add(ell_group, pm, ec_D, C_alpha,
               bn_ctx); // compute elliptic curve addition

  // 6. Convert Pm to hex and write to "Plaintext.txt"
  char *hex_pm =
      EC_POINT_point2hex(ell_group, pm, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
  printf("Plaintext.txt: %s\n", hex_pm);
  Write_File("Plaintext.txt", hex_pm);

  // free up memory
  free(hex_alice_sig);
  free(hex_C);
  free(hex_D);
  free(hex_alice_pub_key);
  free(hex_sk);
  free(hex_pm);
  EC_POINT_free(alice_pub_key); // frees up memory for EX_POINT objects
  EC_POINT_free(ec_C);
  EC_POINT_free(ec_D);
  EC_POINT_free(C_alpha);
  EC_POINT_free(pm);
  EC_KEY_free(
      eckey_alice); // frees up memory for EC_KEY objects
                    // https://docs.openssl.org/master/man3/EC_KEY_new/#description
  EC_GROUP_free(ell_group); // frees up memory for EC_GROUP objects
  BN_CTX_free(bn_ctx);      // frees up memory for BN_CTX objects
  BN_free(bob_sk);          // frees up memory for BIGNUM objects
  return EXIT_SUCCESS;
}

// Helper functions//
//  Read file
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

// Write to file
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

// Show in hex
void Show_in_Hex(char name[], unsigned char hex[], int hexlen) {
  printf("%s: ", name);
  for (int i = 0; i < hexlen; i++)
    printf("%02x", hex[i]);
  printf("\n");
}

// Convert to hex
void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
  for (int i = 0; i < inputlength; i++) {
    sprintf(&output[2 * i], "%02x", input[i]);
  }
  // printf("Hex format: %s\n", output);  //remove later
}
