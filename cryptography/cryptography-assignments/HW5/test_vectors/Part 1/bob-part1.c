#include <ctype.h>
#include <oqs/common.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

// Function definitions
uint8_t *Read_Hex_File(const char *filename, size_t *data_len);
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len);

int main(int argc, char *argv[]) {
  /* Setup Variables */
  int exit_code = EXIT_FAILURE;
  uint8_t *bob_kyber_private;
  uint8_t *alice_dilithium_public;
  OQS_KEM *kem;
  uint8_t *dilithium_sig;
  uint8_t *kyber_ciphertext;
  OQS_SIG *sig;
  uint8_t *bob_shared_secret;

  /* Initialize liboqs library */
  OQS_init();

  /* Read Bob's Kyber private key (hex file -> bytes) */
  size_t bob_kyber_private_len;
  bob_kyber_private = Read_Hex_File(argv[2], &bob_kyber_private_len);
  if (!bob_kyber_private) {
    fprintf(stderr, "ERROR: Failed to read Bob's Kyber public key file.\n");
    goto cleanup;
  }

  /* Create KEM object for Kyber512 */
  kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
  if (kem == NULL) {
    fprintf(stderr, "ERROR: OQS_KEM_new failed for %s\n",
            OQS_KEM_alg_kyber_512);
    goto cleanup;
  }

  /* Verify length of Bob's private key matches expected length */
  if (bob_kyber_private_len != (size_t)kem->length_secret_key) {
    fprintf(stderr,
            "ERROR: Bob's Kyber private key length mismatch: got %zu, expected "
            "%zu\n",
            bob_kyber_private_len, kem->length_secret_key);
    goto cleanup;
  }

  /* Read Alice's Dilithium public key (hex file -> bytes) */
  size_t alice_dilithium_public_len;
  alice_dilithium_public = Read_Hex_File(argv[1], &alice_dilithium_public_len);
  if (!alice_dilithium_public) {
    fprintf(stderr,
            "ERROR: Failed to read Alice's Dilithium private key file.\n");
    goto cleanup;
  }

  sig = OQS_SIG_new("Dilithium2");
  if (!sig) {
    fprintf(stderr, "ERROR: OQS_SIG_new failed for Dilithium2.\n");
    goto cleanup;
  }

  if (alice_dilithium_public_len != (size_t)sig->length_public_key) {
    fprintf(stderr,
            "ERROR: Alice's Dilithium public key length mismatch: got %zu, "
            "expected %zu.\n",
            alice_dilithium_public_len, sig->length_public_key);
    goto cleanup;
  }

  /* Read Dilithium Signature (hex file -> bytes) */
  size_t dilithium_sig_len;
  dilithium_sig = Read_Hex_File("dilithium_signature.txt", &dilithium_sig_len);
  if (!dilithium_sig) {
    fprintf(stderr, "ERROR: Failed to read Dilithium Signature file.\n");
    goto cleanup;
  }

  if (dilithium_sig_len != (size_t)sig->length_signature) {
    fprintf(stderr,
            "ERROR: Signature length mismatch: got %zu, expected %zu.\n",
            dilithium_sig_len, sig->length_signature);
    goto cleanup;
  }

  /* Read Kyber Ciphertext (hex file -> bytes) */
  size_t kyber_ciphertext_len;
  kyber_ciphertext =
      Read_Hex_File("kyber_ciphertext.txt", &kyber_ciphertext_len);
  if (!kyber_ciphertext) {
    fprintf(stderr, "ERROR: Failed to read Kyber Ciphertext file.\n");
    goto cleanup;
  }

  if (kyber_ciphertext_len != (size_t)kem->length_ciphertext) {
    fprintf(stderr,
            "ERROR: Kyber ciphertext length mismatch: got %zu, expected %zu.\n",
            kyber_ciphertext_len, kem->length_ciphertext);
    goto cleanup;
  }

  /* Verify Dilithium signature */
  if (OQS_SIG_verify(sig, kyber_ciphertext, kyber_ciphertext_len, dilithium_sig,
                     dilithium_sig_len,
                     alice_dilithium_public) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: Signature verification failed! Aborting.\n");
    goto cleanup;
  }

  printf("Signature verified successfully!\n");

  /* Decapsulate the Kyber ciphertext to get Bob's shared secret */
  bob_shared_secret = malloc(kem->length_shared_secret);
  if (!bob_shared_secret) {
    fprintf(stderr, "ERROR: Failed to allocate shared secret buffer.\n");
    goto cleanup;
  }

  if (OQS_KEM_decaps(kem, bob_shared_secret, kyber_ciphertext,
                     bob_kyber_private) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_KEM_decaps failed.\n");
    free(bob_shared_secret);
    goto cleanup;
  }

  /* Write Bob's shared secret to file (Hex) */
  Write_Hex_File("bob_shared_secret.txt", bob_shared_secret,
                 kem->length_shared_secret);
  printf("Bob's shared secret written to bob_shared_secret.txt\n");

  exit_code = EXIT_SUCCESS;

cleanup:
  if (bob_shared_secret)
    free(bob_shared_secret);
  if (dilithium_sig)
    free(dilithium_sig);
  if (kyber_ciphertext)
    free(kyber_ciphertext);
  if (sig)
    OQS_SIG_free(sig);
  if (kem)
    OQS_KEM_free(kem);
  if (bob_kyber_private)
    free(bob_kyber_private);
  if (alice_dilithium_public)
    free(alice_dilithium_public);
  /* Shutdown liboqs */
  OQS_destroy();

  return exit_code;
}

// Read file content
char *Read_File(const char *filename, long *fileLen) {
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
    if (!isxdigit(hex_input[i]) || !isxdigit(hex_input[i + 1])) {
      continue;
    }
    if (bytes >= max_len)
      break;
    sscanf(&hex_input[i], "%2hhx", &output[bytes]);
    bytes++;
  }
  return bytes;
}

// Read hex file
uint8_t *Read_Hex_File(const char *filename, size_t *data_len) {
  long file_len;
  char *content = Read_File(filename, &file_len);
  if (!content) {
    *data_len = 0;
    return NULL;
  }
  uint8_t *data = malloc(file_len / 2 + 1);
  if (!data) {
    free(content);
    *data_len = 0;
    return NULL;
  }
  *data_len = Convert_from_Hex(data, content, file_len / 2 + 1);
  free(content);
  if (*data_len == 0) {
    free(data);
    return NULL;
  }
  return data;
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

// Convert bytes to hex string
void Convert_to_Hex(char *output, const uint8_t *input, size_t len) {
  for (size_t i = 0; i < len; i++) {
    sprintf(output + 2 * i, "%02X", input[i]);
  }
  output[len * 2] = '\0';
}

// Write hex file
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len) {
  char *hex_str = malloc(len * 2 + 1);
  if (!hex_str)
    return;
  Convert_to_Hex(hex_str, data, len);
  Write_File(filename, hex_str);
  free(hex_str);
}
